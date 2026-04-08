#!/usr/bin/env python3
"""erlkoenig TUI — real-time container monitoring, threat detection, network flows.

Usage:
    python3 tools/dashboard.py                     # localhost RabbitMQ
    python3 tools/dashboard.py erlkoenig-dev       # remote broker

Views:
    1  Overview    — SOC screen: key metrics + containers + recent alerts
    2  Threats     — Per-IP actors, bans, top attackers, timeline
    3  Containers  — Resource health, memory bars, lifecycle
    4  Network     — Flow rates, top talkers, recent connections
    5  Events      — Raw event stream (filterable)

Keybindings:
    1-5         Switch view
    ?/h         Help
    j/k         Navigate tables
    Enter       Attach to container logs
    f           Filter events
    c           Clear
    q           Quit

Requires: pip install textual pika
"""

import sys
import json
import threading
import time
from datetime import datetime
from collections import defaultdict

import pika
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Header, Footer, Static, DataTable, RichLog, Input
from textual.containers import Vertical
from textual import on

EXCHANGE = "erlkoenig.events"
LOG_STREAM_PREFIX = "erlkoenig.log."


# ═══════════════════════════════════════════════════════════
# State
# ═══════════════════════════════════════════════════════════

def fmt_bytes(b):
    if not b or b == 0:
        return "-"
    if b < 1024:
        return f"{b}B"
    if b < 1048576:
        return f"{b / 1024:.1f}K"
    if b < 1073741824:
        return f"{b / 1048576:.1f}M"
    return f"{b / 1073741824:.1f}G"


def mem_bar(current, limit, width=8):
    if not limit or limit == 0:
        return "░" * width
    pct = min(1.0, current / limit)
    filled = int(pct * width)
    color = "green" if pct < 0.6 else "yellow" if pct < 0.8 else "red"
    bar = "█" * filled + "░" * (width - filled)
    return f"[{color}]{bar}[/] {pct:.0%}"


class ClusterState:
    """Tracks entire cluster state from AMQP events."""

    def __init__(self):
        self.containers = {}
        self.counters = {}
        self.events = []
        self.node = "?"

        # Guard / Threats
        self.threats = {}
        self.threat_history = []
        self.guard_stats = {"actors": 0, "bans": 0, "events_seen": 0}
        self.honeypots = 0
        self.suspects = 0
        self.slow_scans = 0
        self.ban_failures = 0
        self.top_attackers = defaultdict(lambda: {"bans": 0, "reasons": set()})

        # Network
        self.flows_active = 0
        self.flows_new_count = 0
        self.flows_destroy_count = 0
        self.flows_new_window = []  # timestamps for rate calc
        self.recent_connections = []
        self.top_talkers = defaultdict(int)

        # Lifecycle
        self.lifecycle_events = []

    def handle_event(self, routing_key, body):
        parts = routing_key.split(".")
        if len(parts) < 3:
            return routing_key

        payload = body.get("payload", body)
        category = parts[0]
        entity = parts[1]
        event = ".".join(parts[2:])

        if "node" in body:
            self.node = body["node"]

        result = None
        if category == "container":
            self._handle_container(entity, event, payload)
        elif category == "stats":
            self._handle_stats(entity, event, payload)
            result = "skip"  # stats update table, not event log
        elif category == "firewall":
            self._handle_firewall(entity, event, payload)
        elif category == "guard":
            result = self._handle_guard(entity, event, payload)
        elif category == "conntrack":
            self._handle_conntrack(entity, event, payload)
            result = "skip"  # conntrack updates counters, not event log

        if result == "skip":
            return routing_key

        ts = body.get("ts", "")
        if isinstance(ts, (int, float)):
            ts = datetime.fromtimestamp(ts / 1000).strftime("%H:%M:%S")
        elif not ts:
            ts = datetime.now().strftime("%H:%M:%S")
        else:
            ts = str(ts)[:8]

        summary = self._summarize(category, entity, event, payload)
        entry = (ts, routing_key, summary, category)
        self.events.append(entry)
        if len(self.events) > 500:
            self.events = self.events[-500:]
        return routing_key

    def _handle_container(self, name, event, body):
        now = datetime.now().strftime("%H:%M:%S")
        if event in ("started", "running"):
            self.containers.setdefault(name, {})
            self.containers[name].update({
                "state": "running",
                "ip": body.get("ip", ""),
                "restarts": body.get("restart_count", 0),
                "started_at": now,
            })
            self.lifecycle_events.append((now, name, "started", body.get("ip", "")))
        elif event == "stopped":
            if name in self.containers:
                self.containers[name]["state"] = "stopped"
            self.lifecycle_events.append((now, name, "stopped", ""))
        elif event in ("failed", "oom"):
            if name in self.containers:
                self.containers[name]["state"] = event
            self.lifecycle_events.append((now, name, event, ""))
        if len(self.lifecycle_events) > 50:
            self.lifecycle_events = self.lifecycle_events[-50:]

    def _handle_stats(self, name, metric, body):
        self.containers.setdefault(name, {
            "state": "running", "ip": "", "restarts": 0
        })
        ct = self.containers[name]
        if metric == "memory":
            ct["mem_bytes"] = body.get("current", body.get("usage_bytes", 0))
            ct["mem_limit"] = body.get("limit", body.get("limit_bytes", 0))
        elif metric == "cpu":
            ct["cpu_pct"] = body.get("percent", body.get("usage_pct", 0))
        elif metric == "pids":
            ct["pids"] = body.get("current", body.get("count", 0))
            ct["pids_limit"] = body.get("limit", 0)
        elif metric == "pressure":
            ct["psi_some"] = body.get("some_avg10", 0)
            ct["psi_full"] = body.get("full_avg10", 0)

    def _handle_firewall(self, chain, event, body):
        if event == "drop":
            self.counters[chain] = self.counters.get(chain, 0) + 1

    def _handle_guard(self, entity, event, body):
        ip = body.get("ip", "?")
        now_str = datetime.now().strftime("%H:%M:%S")

        if event == "summary":
            # guard.stats.summary — metric, not an event
            self.guard_stats = {
                "actors": body.get("actors", 0),
                "bans": body.get("bans", 0),
                "events_seen": body.get("events_seen", 0),
            }
            return "skip"

        if event == "ban":
            self.guard_stats["bans"] = self.guard_stats.get("bans", 0) + 1
            dur = body.get("duration", 0)
            reason = body.get("reason", "?")
            bc = body.get("ban_count", 1)
            self.threats[ip] = {
                "state": "BANNED", "reason": reason,
                "duration": dur, "ban_count": bc,
                "ports": body.get("ports", []), "since": now_str,
            }
            self.top_attackers[ip]["bans"] += 1
            self.top_attackers[ip]["reasons"].add(str(reason))
        elif event == "unban":
            self.guard_stats["bans"] = max(0, self.guard_stats.get("bans", 0) - 1)
            if ip in self.threats:
                self.threats[ip]["state"] = "PROBATION"
                self.threats[ip]["since"] = now_str
        elif event == "honeypot":
            self.honeypots += 1
            port = body.get("port", "?")
            self.threats[ip] = {
                "state": "BANNED", "reason": "honeypot",
                "duration": body.get("duration", 86400), "ban_count": 1,
                "ports": [port], "since": now_str,
            }
            self.top_attackers[ip]["bans"] += 1
            self.top_attackers[ip]["reasons"].add("honeypot")
        elif event == "suspect":
            self.suspects += 1
            self.threats.setdefault(ip, {
                "state": "SUSPECT", "reason": "suspect", "duration": 0,
                "ban_count": 0, "ports": [], "since": now_str,
            })
            self.threats[ip]["state"] = "SUSPECT"
            self.threats[ip]["ports"] = body.get("ports", [])
        elif event == "slow_scan":
            self.slow_scans += 1
        elif event == "ban_failed":
            self.ban_failures += 1
            self.threats.setdefault(ip, {
                "state": "BAN_FAIL", "reason": "?", "duration": 0,
                "ban_count": 0, "ports": [], "since": now_str,
            })
            self.threats[ip]["state"] = "BAN_FAIL"

        self.threat_history.append((now_str, event, ip, body))
        if len(self.threat_history) > 200:
            self.threat_history = self.threat_history[-200:]

    def _handle_conntrack(self, entity, event, body):
        now = time.time()
        if event == "new":
            self.flows_active += 1
            self.flows_new_count += 1
            self.flows_new_window.append(now)
            src = body.get("src", "")
            dst = body.get("dst", "")
            if src and dst:
                self.top_talkers[f"{src} → {dst}"] += 1
                sport = body.get("sport", "")
                dport = body.get("dport", "")
                proto = body.get("proto_name", body.get("proto", ""))
                self.recent_connections.append((
                    datetime.now().strftime("%H:%M:%S"),
                    proto, src, sport, dst, dport, "new"
                ))
        elif event == "destroy":
            self.flows_active = max(0, self.flows_active - 1)
            self.flows_destroy_count += 1

        # Trim
        cutoff = now - 60
        self.flows_new_window = [t for t in self.flows_new_window if t > cutoff]
        if len(self.recent_connections) > 20:
            self.recent_connections = self.recent_connections[-20:]

    def flows_per_sec(self):
        if not self.flows_new_window:
            return 0
        elapsed = max(1, time.time() - self.flows_new_window[0])
        return len(self.flows_new_window) / elapsed

    def _summarize(self, cat, entity, event, body):
        if cat == "guard":
            ip = body.get("ip", "")
            reason = body.get("reason", "")
            parts = [ip]
            if reason:
                parts.append(f"({reason})")
            port = body.get("port", "")
            if port:
                parts.append(f"port={port}")
            dur = body.get("duration", "")
            if dur:
                parts.append(f"dur={dur}s")
            return " ".join(str(p) for p in parts)
        elif cat == "firewall":
            return body.get("src", body.get("prefix", ""))
        elif cat == "container":
            return body.get("ip", "")
        return ""


# ═══════════════════════════════════════════════════════════
# AMQP Thread
# ═══════════════════════════════════════════════════════════

class AmqpThread:
    """Background thread consuming AMQP events."""

    def __init__(self, host, state, lock, queue):
        self.host = host
        self.state = state
        self.lock = lock
        self.queue = queue
        self._conn = None

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        while True:
            try:
                creds = pika.PlainCredentials("erlkoenig", "erlkoenig")
                params = pika.ConnectionParameters(
                    host=self.host, port=5672, credentials=creds, heartbeat=30,
                )
                self._conn = pika.BlockingConnection(params)
                ch = self._conn.channel()
                ch.exchange_declare(
                    exchange=EXCHANGE, exchange_type="topic", durable=True
                )
                result = ch.queue_declare(queue="", exclusive=True)
                q = result.method.queue
                ch.queue_bind(exchange=EXCHANGE, queue=q, routing_key="#")
                ch.basic_consume(
                    queue=q, on_message_callback=self._on_event, auto_ack=True
                )
                ch.start_consuming()
            except Exception:
                self._conn = None
                time.sleep(2)

    def _on_event(self, ch, method, props, body_bytes):
        try:
            body = json.loads(body_bytes)
            key = body.get("key", method.routing_key)
            with self.lock:
                self.state.handle_event(key, body)
                self.queue.append(("event", key))
        except Exception:
            pass

    def attach_logs(self, container_name, callback):
        def _consume():
            try:
                creds = pika.PlainCredentials("erlkoenig", "erlkoenig")
                params = pika.ConnectionParameters(
                    host=self.host, port=5672, credentials=creds, heartbeat=30,
                )
                conn = pika.BlockingConnection(params)
                ch = conn.channel()
                stream_name = f"{LOG_STREAM_PREFIX}{container_name}"
                try:
                    ch.queue_declare(queue=stream_name, durable=True, passive=True)
                    ch.basic_qos(prefetch_count=100)
                    ch.basic_consume(
                        queue=stream_name,
                        on_message_callback=lambda c, m, p, b: callback(
                            container_name,
                            (p.headers or {}).get("fd", "stdout"),
                            b.decode("utf-8", errors="replace")
                        ),
                        auto_ack=False,
                        arguments={"x-stream-offset": "last"}
                    )
                    ch.start_consuming()
                except Exception:
                    conn = pika.BlockingConnection(params)
                    ch = conn.channel()
                    callback(container_name, "system",
                             f"[red]Stream {stream_name} not found[/]")
            except Exception as e:
                callback(container_name, "system", f"[red]Error: {e}[/]")

        threading.Thread(target=_consume, daemon=True).start()


# ═══════════════════════════════════════════════════════════
# Log Screen
# ═══════════════════════════════════════════════════════════

class LogScreen(Screen):
    BINDINGS = [Binding("escape", "go_back", "Back")]

    def __init__(self, container_name, amqp):
        super().__init__()
        self.container_name = container_name
        self.amqp = amqp
        self._log_queue = []
        self._lock = threading.Lock()

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(id="log-output", max_lines=2000, markup=True)
        yield Footer()

    def on_mount(self):
        self.title = f"logs: {self.container_name}"
        log = self.query_one("#log-output", RichLog)
        log.write(f"[dim]Attaching to {self.container_name}...[/]")
        self.amqp.attach_logs(self.container_name, self._on_log)
        self.set_interval(0.2, self._flush)

    def _on_log(self, name, fd, text):
        with self._lock:
            self._log_queue.append((fd, text))

    def _flush(self):
        with self._lock:
            items, self._log_queue = self._log_queue[:], []
        log = self.query_one("#log-output", RichLog)
        for fd, text in items:
            for line in text.rstrip("\n").split("\n"):
                if not line:
                    continue
                color = "white" if fd == "stdout" else "red" if fd == "stderr" else "cyan"
                log.write(f"[dim]{fd}[/] [{color}]{line}[/]")

    def action_go_back(self):
        self.app.pop_screen()


# ═══════════════════════════════════════════════════════════
# Main App
# ═══════════════════════════════════════════════════════════

class ErlkoenigTUI(App):
    CSS = """
    Screen { layout: vertical; background: $surface; }

    /* ── Overview ─────────────────────────── */
    #overview-metrics {
        height: 3;
        border: heavy cyan;
        border-title-color: cyan;
        border-title-style: bold;
        padding: 0 2;
        margin: 0 0 1 0;
    }
    #overview-table {
        height: auto;
        max-height: 40%;
        margin: 0 0 1 0;
    }
    #overview-recent {
        height: 1fr;
        min-height: 5;
        border: round $accent;
        border-title-color: $accent;
        padding: 0 1;
    }

    /* ── Threats ──────────────────────────── */
    #threat-table {
        height: auto;
        max-height: 30%;
        margin: 0 0 1 0;
    }
    #threat-stats {
        height: 3;
        border: heavy red 40%;
        border-title-color: red;
        border-title-style: bold;
        padding: 0 2;
        margin: 0 0 1 0;
    }
    #threat-attackers {
        height: auto;
        max-height: 20%;
        margin: 0 0 1 0;
    }
    #threat-log {
        height: 1fr;
        min-height: 5;
        border: round $accent;
        border-title-color: $accent;
        padding: 0 1;
    }

    /* ── Containers ───────────────────────── */
    #container-table {
        height: auto;
        max-height: 55%;
        margin: 0 0 1 0;
    }
    #container-lifecycle {
        height: 1fr;
        min-height: 5;
        border: round $accent;
        border-title-color: $accent;
        padding: 0 1;
    }

    /* ── Network ──────────────────────────── */
    #network-metrics {
        height: 3;
        border: heavy blue 40%;
        border-title-color: blue;
        border-title-style: bold;
        padding: 0 2;
        margin: 0 0 1 0;
    }
    #network-talkers {
        height: auto;
        max-height: 40%;
        margin: 0 0 1 0;
    }
    #network-recent {
        height: 1fr;
        min-height: 5;
        border: round $accent;
        border-title-color: $accent;
        padding: 0 1;
    }

    /* ── Events ───────────────────────────── */
    #event-full { height: 1fr; padding: 0 1; }

    /* ── Shared ───────────────────────────── */
    #filter-input {
        dock: bottom;
        display: none;
        height: 3;
        border: heavy magenta;
    }
    TabbedContent { height: 1fr; }
    TabPane { height: 1fr; padding: 0 1; }
    DataTable { scrollbar-size: 1 1; }
    """

    TITLE = "erlkoenig"
    SUB_TITLE = "reactive container firewall"

    BINDINGS = [
        Binding("question_mark", "help", "?", key_display="?"),
        Binding("1", "tab_1", "Overview"),
        Binding("2", "tab_2", "Threats"),
        Binding("3", "tab_3", "Containers"),
        Binding("4", "tab_4", "Network"),
        Binding("5", "tab_5", "Events"),
        Binding("f", "filter", "Filter"),
        Binding("c", "clear", "Clear"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, host="localhost"):
        super().__init__()
        self.amqp_host = host
        self.state = ClusterState()
        self._event_queue = []
        self._lock = threading.Lock()
        self._filter = ""
        self._amqp = None
        self._last_threat_idx = 0

    def compose(self) -> ComposeResult:
        from textual.widgets import TabbedContent, TabPane
        yield Header()
        with TabbedContent(initial="overview"):
            with TabPane("Overview", id="overview"):
                yield Static(id="overview-metrics")
                yield DataTable(id="overview-table")
                yield RichLog(id="overview-recent", max_lines=50, markup=True)
            with TabPane("Threats", id="threats"):
                yield DataTable(id="threat-table")
                yield Static(id="threat-stats")
                yield DataTable(id="threat-attackers")
                yield RichLog(id="threat-log", max_lines=200, markup=True)
            with TabPane("Health", id="containers"):
                yield DataTable(id="container-table")
                yield RichLog(id="container-lifecycle", max_lines=50, markup=True)
            with TabPane("Network", id="network"):
                yield Static(id="network-metrics")
                yield DataTable(id="network-talkers")
                yield RichLog(id="network-recent", max_lines=30, markup=True)
            with TabPane("Stream", id="events"):
                yield RichLog(id="event-full", max_lines=500, markup=True)
        yield Input(placeholder="Filter (e.g. 'guard', 'container')...", id="filter-input")
        yield Footer()

    def on_mount(self):
        # Overview
        t = self.query_one("#overview-table", DataTable)
        t.add_columns("CONTAINER", "STATE", "IP", "MEMORY", "CPU", "PIDs", "PSI")
        t.cursor_type = "row"
        t.zebra_stripes = True
        self.query_one("#overview-metrics").border_title = " situational awareness "
        self.query_one("#overview-recent").border_title = " recent alerts "

        # Threats
        tt = self.query_one("#threat-table", DataTable)
        tt.add_columns("IP", "STATE", "REASON", "PORTS", "BAN#", "DURATION", "SINCE")
        tt.zebra_stripes = True
        self.query_one("#threat-stats").border_title = " threat mesh "
        self.query_one("#threat-log").border_title = " threat timeline "

        # Top attackers
        ta = self.query_one("#threat-attackers", DataTable)
        ta.add_columns("IP", "BANS", "ATTACK PATTERN")
        ta.zebra_stripes = True

        # Containers
        ct = self.query_one("#container-table", DataTable)
        ct.add_columns("CONTAINER", "STATE", "MEMORY", "CPU", "PIDs", "PSI", "OOM", "RESTARTS")
        ct.cursor_type = "row"
        ct.zebra_stripes = True
        self.query_one("#container-lifecycle").border_title = " lifecycle "

        # Network
        nt = self.query_one("#network-talkers", DataTable)
        nt.add_columns("FLOW", "CONNECTIONS")
        nt.zebra_stripes = True
        self.query_one("#network-metrics").border_title = " connection flows "
        self.query_one("#network-recent").border_title = " recent connections "

        # Start AMQP
        self._amqp = AmqpThread(self.amqp_host, self.state, self._lock, self._event_queue)
        self._amqp.start()
        self.set_interval(0.5, self._tick)

    def _tick(self):
        with self._lock:
            new_events = list(self._event_queue)
            self._event_queue.clear()

        if not new_events:
            return

        self._refresh_overview()
        self._refresh_threats()
        self._refresh_containers()
        self._refresh_network()
        self._refresh_events(new_events)

        n = len(self.state.containers)
        self.sub_title = f"{self.state.node} — {n} containers"

    # ── Overview ────────────────────────────────

    def _refresh_overview(self):
        s = self.state
        gs = s.guard_stats
        actors = gs.get("actors", 0)
        bans = gs.get("bans", 0)
        flows = s.flows_active
        fps = s.flows_per_sec()
        drops = sum(s.counters.values())
        cts = len(s.containers)

        sep = " [dim]│[/] "
        ct_color = "green" if cts > 0 else "red"
        ban_color = "red bold" if bans > 0 else "dim"
        hp_color = "yellow" if s.honeypots > 0 else "dim"
        metrics = (
            f"  [{ct_color}]{cts}[/] containers"
            f"{sep}[cyan]{actors}[/] actors"
            f"{sep}[{ban_color}]{bans}[/] banned"
            f"{sep}{flows} flows ({fps:.0f}/s)"
            f"{sep}{drops} drops"
            f"{sep}[{hp_color}]{s.honeypots}[/] honeypots"
            f"{sep}{s.suspects} suspects"
        )
        try:
            self.query_one("#overview-metrics", Static).update(metrics)
        except Exception:
            pass

        # Container table
        try:
            table = self.query_one("#overview-table", DataTable)
            table.clear()
            for name in sorted(s.containers.keys()):
                ct = s.containers[name]
                st = ct.get("state", "?")
                state_map = {
                    "running": "[green]● run[/]", "stopped": "[dim]○ stop[/]",
                    "oom": "[red]✗ oom[/]", "failed": "[red]✗ fail[/]",
                }
                ip = ct.get("ip", "")
                mem = mem_bar(ct.get("mem_bytes", 0), ct.get("mem_limit", 0))
                cpu = f'{ct.get("cpu_pct", 0):.1f}%'
                pids = f'{ct.get("pids", 0)}/{ct.get("pids_limit", 0)}' if ct.get("pids_limit") else str(ct.get("pids", 0))
                psi = f'{ct.get("psi_some", 0):.1f}%' if ct.get("psi_some") else "-"
                table.add_row(name, state_map.get(st, f"? {st}"), ip, mem, cpu, pids, psi)
        except Exception:
            pass

        # Recent alerts (only guard + lifecycle, NO conntrack/stats)
        try:
            log = self.query_one("#overview-recent", RichLog)
            with self._lock:
                events = list(s.events)
            for ts, key, summary, cat in events[-3:]:
                if cat in ("guard", "container", "firewall"):
                    colors = {"guard": "yellow", "container": "green", "firewall": "red"}
                    color = colors.get(cat, "white")
                    detail = f"  {summary}" if summary else ""
                    log.write(f"[dim]{ts}[/]  [{color}]{key}[/]{detail}")
        except Exception:
            pass

    # ── Threats ──────────────────────────────────

    def _refresh_threats(self):
        s = self.state
        state_styles = {
            "BANNED": "[red bold]BANNED[/]", "SUSPECT": "[yellow]SUSPECT[/]",
            "PROBATION": "[cyan]PROBATION[/]", "BAN_FAIL": "[red]BAN_FAIL[/]",
        }

        try:
            tt = self.query_one("#threat-table", DataTable)
            tt.clear()
            for ip in sorted(s.threats.keys()):
                t = s.threats[ip]
                state = state_styles.get(t["state"], t["state"])
                ports = ", ".join(str(p) for p in t.get("ports", [])[:5])
                dur = f'{t.get("duration", 0)}s' if t.get("duration") else "-"
                tt.add_row(ip, state, t.get("reason", ""), ports,
                           str(t.get("ban_count", 0)), dur, t.get("since", ""))
        except Exception:
            pass

        # Stats bar
        gs = s.guard_stats
        banned = sum(1 for t in s.threats.values() if t["state"] == "BANNED")
        suspect = sum(1 for t in s.threats.values() if t["state"] == "SUSPECT")
        probation = sum(1 for t in s.threats.values() if t["state"] == "PROBATION")
        sep = " [dim]│[/] "
        ban_c = "red bold" if banned > 0 else "dim"
        sus_c = "yellow" if suspect > 0 else "dim"
        prob_c = "cyan" if probation > 0 else "dim"
        stats = (
            f"  [cyan]{gs.get('actors', 0)}[/] actors"
            f"{sep}[{ban_c}]{banned}[/] banned"
            f"{sep}[{sus_c}]{suspect}[/] suspect"
            f"{sep}[{prob_c}]{probation}[/] probation"
            f"{sep}{s.honeypots} honeypots"
            f"{sep}{s.slow_scans} slow scans"
            f"{sep}{gs.get('events_seen', 0)} events"
        )
        if s.ban_failures:
            stats += f"{sep}[red bold]{s.ban_failures} failures[/]"
        try:
            self.query_one("#threat-stats", Static).update(stats)
        except Exception:
            pass

        # Top attackers
        try:
            ta = self.query_one("#threat-attackers", DataTable)
            ta.clear()
            sorted_attackers = sorted(s.top_attackers.items(),
                                       key=lambda x: x[1]["bans"], reverse=True)[:10]
            for ip, info in sorted_attackers:
                reasons = ", ".join(sorted(info["reasons"]))
                ta.add_row(ip, str(info["bans"]), reasons)
        except Exception:
            pass

        # Threat timeline
        try:
            tlog = self.query_one("#threat-log", RichLog)
            colors = {
                "ban": "red", "unban": "green", "honeypot": "yellow",
                "suspect": "cyan", "slow_scan": "magenta", "ban_failed": "red bold",
            }
            for ts, event, ip, body in s.threat_history[self._last_threat_idx:]:
                color = colors.get(event, "white")
                reason = body.get("reason", "")
                port = body.get("port", "")
                detail = ""
                if reason:
                    detail += f" reason={reason}"
                if port:
                    detail += f" port={port}"
                dur = body.get("duration", "")
                if dur:
                    detail += f" dur={dur}s"
                tlog.write(f"[dim]{ts}[/]  [{color}]{event:12s}[/]  {ip}{detail}")
            self._last_threat_idx = len(s.threat_history)
        except Exception:
            pass

    # ── Containers ──────────────────────────────

    def _refresh_containers(self):
        s = self.state
        try:
            ct = self.query_one("#container-table", DataTable)
            ct.clear()
            for name in sorted(s.containers.keys()):
                c = s.containers[name]
                st = c.get("state", "?")
                state_map = {
                    "running": "[green]● run[/]", "stopped": "[dim]○ stop[/]",
                    "oom": "[red]✗ oom[/]", "failed": "[red]✗ fail[/]",
                }
                mem = mem_bar(c.get("mem_bytes", 0), c.get("mem_limit", 0), width=12)
                cpu = f'{c.get("cpu_pct", 0):.1f}%'
                pids = f'{c.get("pids", 0)}/{c.get("pids_limit", 0)}' if c.get("pids_limit") else str(c.get("pids", 0))
                psi = c.get("psi_some", 0)
                psi_str = f"[green]{psi:.1f}%[/]" if psi < 5 else f"[yellow]{psi:.1f}%[/]" if psi < 20 else f"[red]{psi:.1f}%[/]"
                oom = str(c.get("oom_events", 0)) if c.get("oom_events") else "-"
                restarts = str(c.get("restarts", 0))
                ct.add_row(name, state_map.get(st, st), mem, cpu, pids, psi_str, oom, restarts)
        except Exception:
            pass

        # Lifecycle events
        try:
            llog = self.query_one("#container-lifecycle", RichLog)
            # Write only new ones
            count = getattr(self, '_last_lifecycle_idx', 0)
            for ts, name, event, ip in s.lifecycle_events[count:]:
                colors = {"started": "green", "stopped": "dim", "failed": "red", "oom": "red bold"}
                color = colors.get(event, "white")
                detail = f" ip={ip}" if ip else ""
                llog.write(f"[dim]{ts}[/]  [{color}]{event:8s}[/]  {name}{detail}")
            self._last_lifecycle_idx = len(s.lifecycle_events)
        except Exception:
            pass

    # ── Network ─────────────────────────────────

    def _refresh_network(self):
        s = self.state
        fps = s.flows_per_sec()
        sep = " [dim]│[/] "
        metrics = (
            f"  [blue]{s.flows_active}[/] active flows"
            f"{sep}[cyan]{fps:.1f}[/] new/s"
            f"{sep}{s.flows_new_count} total new"
            f"{sep}{s.flows_destroy_count} total closed"
        )
        try:
            self.query_one("#network-metrics", Static).update(metrics)
        except Exception:
            pass

        # Top talkers
        try:
            nt = self.query_one("#network-talkers", DataTable)
            nt.clear()
            sorted_talkers = sorted(s.top_talkers.items(),
                                     key=lambda x: x[1], reverse=True)[:15]
            for flow, count in sorted_talkers:
                nt.add_row(flow, str(count))
        except Exception:
            pass

        # Recent connections (last 10)
        try:
            nlog = self.query_one("#network-recent", RichLog)
            count = getattr(self, '_last_conn_idx', 0)
            for ts, proto, src, sport, dst, dport, event in s.recent_connections[count:]:
                src_str = f"{src}:{sport}" if sport else src
                dst_str = f"{dst}:{dport}" if dport else dst
                nlog.write(f"[dim]{ts}[/]  {proto} {src_str} → {dst_str}")
            self._last_conn_idx = len(s.recent_connections)
        except Exception:
            pass

    # ── Events (raw) ────────────────────────────

    def _refresh_events(self, new_events):
        with self._lock:
            events = list(self.state.events)
        try:
            log = self.query_one("#event-full", RichLog)
            for ts, key, summary, cat in events[-len(new_events):]:
                if self._filter and self._filter not in key:
                    continue
                colors = {
                    "container": "green", "stats": "blue",
                    "firewall": "red", "guard": "yellow",
                    "conntrack": "cyan",
                }
                color = colors.get(cat, "white")
                detail = f"  {summary}" if summary else ""
                log.write(f"[dim]{ts}[/]  [{color}]{key}[/]{detail}")
        except Exception:
            pass

    # ── Actions ──────────────────────────────────

    def action_tab_1(self):
        from textual.widgets import TabbedContent
        self.query_one(TabbedContent).active = "overview"

    def action_tab_2(self):
        from textual.widgets import TabbedContent
        self.query_one(TabbedContent).active = "threats"

    def action_tab_3(self):
        from textual.widgets import TabbedContent
        self.query_one(TabbedContent).active = "containers"

    def action_tab_4(self):
        from textual.widgets import TabbedContent
        self.query_one(TabbedContent).active = "network"

    def action_tab_5(self):
        from textual.widgets import TabbedContent
        self.query_one(TabbedContent).active = "events"

    def action_help(self):
        self.notify(
            "1=Overview  2=Threats  3=Containers  4=Network  5=Events  "
            "f=Filter  c=Clear  Enter=Logs  q=Quit",
            title="Keybindings", timeout=10
        )

    def action_filter(self):
        inp = self.query_one("#filter-input", Input)
        inp.display = True
        inp.focus()

    def on_input_submitted(self, event: Input.Submitted):
        inp = self.query_one("#filter-input", Input)
        self._filter = inp.value.strip()
        inp.display = False
        self.notify(f"Filter: {self._filter}" if self._filter else "Filter cleared")

    def action_clear(self):
        for rid in ("#overview-recent", "#threat-log", "#container-lifecycle",
                    "#network-recent", "#event-full"):
            try:
                self.query_one(rid, RichLog).clear()
            except Exception:
                pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        row = event.data_table.get_row(event.row_key)
        name = row[0]
        if name in self.state.containers and self._amqp:
            self.push_screen(LogScreen(name, self._amqp))


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    app = ErlkoenigTUI(host=host)
    app.run()


if __name__ == "__main__":
    main()
