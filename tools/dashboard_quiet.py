#!/usr/bin/env python3
"""Quiet erlkoenig AMQP dashboard.

The dashboard consumes the full AMQP exchange so counters stay current, but the
visible stream focuses on operator signals: structured errors, container
lifecycle, audit/capability problems and threat decisions. High-volume stats
and conntrack events are counted, not printed.
"""

import json
import os
import queue
import sys
import threading
import time
from collections import Counter, deque
from datetime import datetime

import pika
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Header, RichLog, Static

EXCHANGE = "erlkoenig.events"
INTERESTING_PREFIXES = ("error.", "container.", "firewall.", "guard.", "audit.", "capability.")


def now_hms():
    return datetime.now().strftime("%H:%M:%S")


def event_time(body):
    ts = body.get("ts") or body.get("payload", {}).get("ts_ms")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts / 1000).strftime("%H:%M:%S")
    if isinstance(ts, str) and len(ts) >= 19:
        return ts[11:19] if "T" in ts else ts[:8]
    return now_hms()


def short(value, limit=90):
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "..."


def fmt_bytes(value):
    if not value:
        return "-"
    for suffix, factor in (("G", 1073741824), ("M", 1048576), ("K", 1024)):
        if value >= factor:
            return f"{value / factor:.1f}{suffix}"
    return f"{value}B"


def color_for(kind, severity=None):
    if severity == "critical":
        return "bold bright_red"
    if kind == "error":
        return "red"
    if kind == "container":
        return "green"
    if kind == "guard":
        return "yellow"
    if kind == "audit":
        return "cyan"
    if kind == "capability":
        return "magenta"
    return "white"


class State:
    def __init__(self):
        self.started_at = time.time()
        self.node = "?"
        self.connected = False
        self.last_error = ""
        self.last_event_at = None
        self.recent_events = deque(maxlen=1000)
        self.counts = Counter()
        self.hidden_noise = Counter()
        self.error_counts = Counter()
        self.guard_counts = Counter()
        self.guard_stats = {}
        self.incidents = deque(maxlen=220)
        self.lifecycle = deque(maxlen=180)
        self.raw = deque(maxlen=260)
        self.containers = {}
        self.threats = {}
        self.audit_breaks = 0
        self.unmet_caps = 0

    def ingest(self, routing_key, body):
        seen_at = time.time()
        self.last_event_at = seen_at
        self.recent_events.append(seen_at)
        category = routing_key.split(".", 1)[0]
        payload = body.get("payload", {})
        self.counts[category] += 1
        if body.get("node"):
            self.node = body["node"]

        if routing_key == "guard.stats.summary":
            self.hidden_noise["guard_summary"] += 1
            self.guard_stats = {
                "actors": payload.get("actors", 0),
                "bans": payload.get("bans", 0),
                "events_seen": payload.get("events_seen", 0),
            }
            return []

        if routing_key.startswith("stats.") or routing_key.startswith("conntrack."):
            self.hidden_noise[category] += 1
            self._ingest_health(routing_key, payload)
            return []

        ts = event_time(body)
        if routing_key.startswith("error."):
            item = self._error_item(ts, routing_key, payload)
            self.incidents.appendleft(item)
            self.raw.appendleft(item)
            self.error_counts[f"{payload.get('type', '?')}.{payload.get('reason', '?')}"] += 1
            return [("incident", item)]
        if routing_key.startswith("container."):
            item = self._container_item(ts, routing_key, payload)
            self.lifecycle.appendleft(item)
            self.raw.appendleft(item)
            return [("lifecycle", item)]
        if routing_key.startswith("guard."):
            item = self._guard_item(ts, routing_key, payload)
            self.incidents.appendleft(item)
            self.raw.appendleft(item)
            return [("incident", item)]
        if routing_key.startswith("firewall."):
            item = self._firewall_item(ts, routing_key, payload)
            self.raw.appendleft(item)
            return [("raw", item)]
        if routing_key.startswith("audit."):
            item = self._audit_item(ts, routing_key, payload)
            self.incidents.appendleft(item)
            self.raw.appendleft(item)
            return [("incident", item)]
        if routing_key.startswith("capability."):
            item = self._capability_item(ts, routing_key, payload)
            self.incidents.appendleft(item)
            self.raw.appendleft(item)
            return [("incident", item)]

        if routing_key.startswith(INTERESTING_PREFIXES):
            item = self._generic_item(ts, routing_key, category, payload)
            self.raw.appendleft(item)
            return [("raw", item)]
        return []

    def _ingest_health(self, key, payload):
        parts = key.split(".")
        if len(parts) < 3 or not key.startswith("stats."):
            return
        name = parts[1]
        metric = parts[2]
        ct = self.containers.setdefault(name, {"state": "observed"})
        if metric == "memory":
            ct["memory"] = payload.get("current", payload.get("usage_bytes", 0))
            ct["memory_limit"] = payload.get("limit", payload.get("limit_bytes", 0))
        elif metric == "cpu":
            ct["cpu"] = payload.get("percent", payload.get("usage_pct", 0))
        elif metric == "pids":
            ct["pids"] = payload.get("current", payload.get("count", 0))
            ct["pids_limit"] = payload.get("limit", 0)

    def _error_item(self, ts, key, payload):
        subject = payload.get("container") or payload.get("type", "")
        code = payload.get("code", "")
        context = payload.get("context", "")
        data = payload.get("data", {})
        summary = " ".join(part for part in (code, context, short(data)) if part)
        return self._item(ts, key, "error", payload.get("severity", "error"), subject, summary)

    def _container_item(self, ts, key, payload):
        parts = key.split(".")
        name = payload.get("name") or (parts[1] if len(parts) > 1 else "?")
        event = parts[-1]
        ct = self.containers.setdefault(name, {})
        ct["state"] = event
        if payload.get("ip"):
            ct["ip"] = payload["ip"]
        summary = ""
        if event == "started" and payload.get("os_pid"):
            summary = f"pid={payload.get('os_pid')}"
        elif event == "stopped":
            exit_code = payload.get("exit_code")
            signal = payload.get("signal")
            summary = f"exit={exit_code} signal={signal}"
        elif payload.get("reason"):
            summary = str(payload.get("reason"))
        return self._item(ts, key, "container", None, name, summary)

    def _guard_item(self, ts, key, payload):
        event = key.split(".")[-1]
        ip = payload.get("ip", "?")
        self.guard_counts[event] += 1
        if event in ("ban", "suspect", "honeypot", "slow_scan", "ban_failed"):
            self.threats[ip] = {
                "event": event,
                "reason": payload.get("reason", ""),
                "ports": payload.get("ports", []),
                "ts": ts,
            }
        summary = " ".join(str(x) for x in (
            event,
            payload.get("reason", ""),
            f"ports={payload.get('ports')}" if payload.get("ports") else "",
            f"duration={payload.get('duration')}s" if payload.get("duration") else "",
        ) if x)
        severity = "error" if event in ("ban", "ban_failed") else None
        return self._item(ts, key, "guard", severity, ip, summary)

    def _firewall_item(self, ts, key, payload):
        event = key.split(".")[-1]
        subject = payload.get("counter") or payload.get("chain") or key.split(".")[1]
        if event in ("counter", "drop"):
            packets = payload.get("packets")
            pps = payload.get("pps")
            bps = payload.get("bps")
            summary = f"{event} packets={packets} pps={pps} bps={fmt_bytes(bps)}"
        elif event == "packet":
            src = payload.get("src") or payload.get("src_ip") or "?"
            dst = payload.get("dst") or payload.get("dst_ip") or "?"
            dport = payload.get("dport") or payload.get("dst_port") or ""
            summary = f"packet {src} -> {dst}:{dport}"
        else:
            summary = short(payload)
        severity = "error" if event == "drop" else None
        return self._item(ts, key, "firewall", severity, subject, summary)

    def _audit_item(self, ts, key, payload):
        severity = "critical" if key.endswith(".broken") else None
        if severity:
            self.audit_breaks += 1
        return self._item(ts, key, "audit", severity, payload.get("path", ""), short(payload))

    def _capability_item(self, ts, key, payload):
        self.unmet_caps += 1
        subject = payload.get("name") or payload.get("id", "")
        return self._item(ts, key, "capability", "error", subject,
                          f"{subject} missing {payload.get('capability', key)}")

    def _generic_item(self, ts, key, kind, payload):
        return self._item(ts, key, kind, None, "", short(payload))

    def _item(self, ts, key, kind, severity, subject, summary):
        return {
            "ts": ts,
            "key": key,
            "kind": kind,
            "severity": severity,
            "subject": subject or "",
            "summary": summary or "",
        }


class AmqpConsumer:
    def __init__(self, host, user, password, out):
        self.host = host
        self.user = user
        self.password = password
        self.out = out

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                creds = pika.PlainCredentials(self.user, self.password)
                params = pika.ConnectionParameters(
                    self.host, port=5672, credentials=creds, heartbeat=30,
                    blocked_connection_timeout=5,
                )
                conn = pika.BlockingConnection(params)
                ch = conn.channel()
                ch.exchange_declare(exchange=EXCHANGE, exchange_type="topic", durable=True)
                result = ch.queue_declare("", exclusive=True, auto_delete=True)
                queue_name = result.method.queue
                ch.queue_bind(exchange=EXCHANGE, queue=queue_name, routing_key="#")
                self.out.put(("status", {"connected": True, "error": ""}))
                ch.basic_consume(queue_name, self._on_message, auto_ack=True)
                ch.start_consuming()
            except Exception as exc:
                self.out.put(("status", {"connected": False, "error": str(exc)}))
                time.sleep(2)

    def _on_message(self, _ch, method, _props, body):
        try:
            decoded = json.loads(body.decode("utf-8"))
            key = decoded.get("key", method.routing_key)
            self.out.put(("event", key, decoded))
        except Exception as exc:
            self.out.put(("status", {"connected": False, "error": f"decode: {exc}"}))


class Dashboard(App):
    TITLE = "erlkoenig ops"
    SUB_TITLE = "quiet AMQP incident dashboard"

    BINDINGS = [
        Binding("1", "focus_incidents", "Incidents"),
        Binding("2", "focus_lifecycle", "Lifecycle"),
        Binding("3", "focus_raw", "Raw"),
        Binding("c", "clear", "Clear"),
        Binding("m", "toggle_mouse", "Mouse"),
        Binding("q", "quit", "Quit"),
    ]

    CSS = """
    Screen { layout: vertical; }
    #topline {
        height: 3;
        border: heavy cyan;
        padding: 0 2;
    }
    #main {
        height: 1fr;
        layout: horizontal;
    }
    #left {
        width: 2fr;
        height: 1fr;
    }
    #right {
        width: 1fr;
        height: 1fr;
    }
    #incidents {
        height: 2fr;
        border: round red;
        padding: 0 1;
    }
    #lifecycle {
        height: 1fr;
        border: round green;
        padding: 0 1;
    }
    #containers {
        height: 1fr;
        border: round blue;
    }
    #raw {
        height: 1fr;
        border: round $accent;
        padding: 0 1;
    }
    """

    def __init__(self, host, user, password):
        super().__init__()
        self.state = State()
        self.events = queue.Queue()
        self.consumer = AmqpConsumer(host, user, password, self.events)
        self.mouse_on = True

    def compose(self) -> ComposeResult:
        from textual.containers import Horizontal, Vertical

        yield Header()
        yield Static(id="topline")
        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield RichLog(id="incidents", max_lines=300, markup=True)
                yield DataTable(id="lifecycle")
            with Vertical(id="right"):
                yield DataTable(id="containers")
                yield RichLog(id="raw", max_lines=220, markup=True)
        yield Footer()

    def on_mount(self):
        self.query_one("#incidents", RichLog).border_title = " incidents: errors / bans / audit / capability "
        lifecycle = self.query_one("#lifecycle", DataTable)
        lifecycle.border_title = " lifecycle "
        lifecycle.add_columns("TIME", "NAME", "EVENT", "DETAIL")
        lifecycle.zebra_stripes = True
        self.query_one("#raw", RichLog).border_title = " raw important stream "
        table = self.query_one("#containers", DataTable)
        table.border_title = " containers "
        table.add_columns("NAME", "STATE", "MEM", "CPU", "PIDS")
        table.zebra_stripes = True
        self.consumer.start()
        self.set_interval(0.25, self._drain)
        self.set_interval(1.0, self._refresh_static)

    def _drain(self):
        processed = 0
        while processed < 200:
            try:
                item = self.events.get_nowait()
            except queue.Empty:
                break
            processed += 1
            if item[0] == "status":
                self.state.connected = item[1]["connected"]
                self.state.last_error = item[1]["error"]
                if self.state.connected:
                    self._write_status("AMQP connected")
                else:
                    self._write_status(f"AMQP disconnected: {self.state.last_error}")
                continue

            _tag, key, body = item
            for target, event in self.state.ingest(key, body):
                if target == "incident":
                    self._write_incident(event)
                elif target == "lifecycle":
                    pass
                elif target == "raw":
                    self._write_raw(event)
            if key.startswith(INTERESTING_PREFIXES) and self.state.raw:
                self._write_raw(self.state.raw[0])

        if processed:
            self._refresh_static()

    def _refresh_static(self):
        s = self.state
        conn = "[green]connected[/]" if s.connected else "[red]disconnected[/]"
        total = sum(s.counts.values())
        stats_noise = s.hidden_noise["stats"]
        conntrack_noise = s.hidden_noise["conntrack"]
        guard_summary_noise = s.hidden_noise["guard_summary"]
        noise = sum(s.hidden_noise.values())
        visible = total - noise
        now = time.time()
        recent = sum(1 for ts in s.recent_events if now - ts <= 5)
        rate = recent / 5
        age = "-" if s.last_event_at is None else f"{int(now - s.last_event_at)}s"
        text = (
            f"  AMQP {conn} seen={total} {rate:.1f}/s"
            f" vis={visible} hid={noise}"
            f" inc={len(s.incidents)} lc={len(s.lifecycle)}"
            f" c={len(s.containers)} th={len(s.threats)} last={age}"
            f" [dim]st={stats_noise} ct={conntrack_noise} gs={guard_summary_noise}[/]"
        )
        if s.last_error and not s.connected:
            text += f"  [red]{short(s.last_error, 80)}[/]"
        self.query_one("#topline", Static).update(text)
        self._refresh_lifecycle_table()
        self._refresh_container_table()
        self.sub_title = f"{s.node} - {len(s.incidents)} incidents"

    def _refresh_lifecycle_table(self):
        table = self.query_one("#lifecycle", DataTable)
        table.clear()
        for event in list(self.state.lifecycle)[:12]:
            detail = event.get("summary", "")
            table.add_row(event.get("ts", ""), event.get("subject", ""),
                          event.get("key", "").rsplit(".", 1)[-1],
                          detail)

    def _refresh_container_table(self):
        table = self.query_one("#containers", DataTable)
        table.clear()
        for name in sorted(self.state.containers):
            ct = self.state.containers[name]
            mem = fmt_bytes(ct.get("memory"))
            if ct.get("memory_limit"):
                mem = f"{mem}/{fmt_bytes(ct.get('memory_limit'))}"
            cpu = f"{ct.get('cpu', 0):.1f}%" if "cpu" in ct else "-"
            if ct.get("pids_limit"):
                pids = f"{ct.get('pids', 0)}/{ct.get('pids_limit')}"
            else:
                pids = str(ct.get("pids", "-"))
            table.add_row(name, ct.get("state", "?"), mem, cpu, pids)

    def _write_status(self, message):
        self.query_one("#raw", RichLog).write(
            f"[dim]{now_hms()}[/] [cyan]status[/] {message}"
        )

    def _write_incident(self, event):
        color = color_for(event["kind"], event.get("severity"))
        subject = f" [bold]{event['subject']}[/]" if event.get("subject") else ""
        self.query_one("#incidents", RichLog).write(
            f"[dim]{event['ts']}[/] [{color}]{event['key']}[/]{subject}  {event['summary']}"
        )

    def _write_raw(self, event):
        color = color_for(event["kind"], event.get("severity"))
        self.query_one("#raw", RichLog).write(
            f"[dim]{event['ts']}[/] [{color}]{event['key']}[/] {event['summary']}"
        )

    def action_focus_incidents(self):
        self.query_one("#incidents", RichLog).focus()

    def action_focus_lifecycle(self):
        self.query_one("#lifecycle", DataTable).focus()

    def action_focus_raw(self):
        self.query_one("#raw", RichLog).focus()

    def action_clear(self):
        for selector in ("#incidents", "#raw"):
            self.query_one(selector, RichLog).clear()
        self.state.lifecycle.clear()
        self.query_one("#lifecycle", DataTable).clear()

    def action_toggle_mouse(self):
        if self.mouse_on:
            sys.stdout.write("\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l")
            sys.stdout.flush()
            self.mouse_on = False
            self.notify("Mouse off for terminal selection")
        else:
            sys.stdout.write("\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h")
            sys.stdout.flush()
            self.mouse_on = True
            self.notify("Mouse on")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("AMQP_HOST", "localhost")
    user = os.environ.get("AMQP_USER")
    password = os.environ.get("AMQP_PASS")
    if not user or not password:
        print("error: set AMQP_USER and AMQP_PASS", file=sys.stderr)
        sys.exit(2)
    Dashboard(host, user, password).run()


if __name__ == "__main__":
    main()
