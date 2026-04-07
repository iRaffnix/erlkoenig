#!/usr/bin/env python3
"""erlkoenig TUI — real-time container monitoring and log streaming via AMQP.

Usage:
    python3 tools/dashboard.py                     # localhost RabbitMQ
    python3 tools/dashboard.py erlkoenig-dev       # remote broker

Keybindings:
    ?/h         Help
    1           Dashboard (containers + stats + events)
    2           Events (full-screen event stream)
    3           Logs (attach to container stdout/stderr)
    j/k         Navigate container list
    Enter       Select container for log view
    f           Filter events (type pattern)
    r           Replay: rewind log stream to beginning
    t           Toggle timestamps in log view
    /           Search in current view
    q/Escape    Back / Quit

Requires: pip install textual pika
"""

import sys
import json
import threading
import time
from datetime import datetime

import pika
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import (
    Header, Footer, Static, DataTable, RichLog,
    Input, Label, ListView, ListItem, TabbedContent, TabPane,
)
from textual.containers import Vertical, Horizontal, Container

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


class ClusterState:
    """Tracks entire cluster state from AMQP events."""

    def __init__(self):
        self.containers = {}
        self.counters = {}
        self.events = []
        self.banned = 0
        self.flows = 0
        self.node = "?"
        self.selected_container = None

    def handle_event(self, routing_key, body):
        parts = routing_key.split(".")
        if len(parts) < 3:
            return routing_key

        # v2 envelope: actual data is in "payload" field
        payload = body.get("payload", body)
        category, entity, event = parts[0], parts[1], ".".join(parts[2:])

        if "node" in body:
            self.node = body["node"]

        if category == "container":
            self._handle_container(entity, event, payload)
        elif category == "stats":
            self._handle_stats(entity, event, payload)
        elif category == "firewall":
            self._handle_firewall(entity, event, payload)
        elif category == "guard":
            self._handle_guard(entity, event, payload)
        elif category == "conntrack":
            self._handle_conntrack(entity, event, payload)

        ts = body.get("ts", datetime.now().strftime("%H:%M:%S.%f")[:12])
        if isinstance(ts, (int, float)):
            ts = datetime.fromtimestamp(ts / 1000).strftime("%H:%M:%S.%f")[:12]
        summary = self._summarize(category, entity, event, payload)
        entry = (ts, routing_key, summary, category)
        self.events.append(entry)
        if len(self.events) > 500:
            self.events = self.events[-500:]
        return routing_key

    def _handle_container(self, name, event, body):
        if event in ("started", "running"):
            self.containers.setdefault(name, {})
            self.containers[name].update({
                "state": "running",
                "ip": body.get("ip", ""),
                "restarts": body.get("restart_count", 0),
                "started_at": datetime.now().strftime("%H:%M:%S"),
            })
        elif event == "stopped":
            if name in self.containers:
                self.containers[name]["state"] = "stopped"
        elif event in ("failed", "oom"):
            if name in self.containers:
                self.containers[name]["state"] = event

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
            key = chain
            self.counters[key] = self.counters.get(key, 0) + 1

    def _handle_guard(self, entity, event, body):
        if event == "ban":
            self.banned += 1
        elif event == "unban":
            self.banned = max(0, self.banned - 1)

    def _handle_conntrack(self, entity, event, body):
        if event == "new":
            self.flows += 1
        elif event == "destroy":
            self.flows = max(0, self.flows - 1)

    def _summarize(self, cat, entity, event, body):
        if cat == "stats":
            if event == "memory":
                return fmt_bytes(body.get("current", body.get("usage_bytes", 0)))
            elif event == "cpu":
                return f'{body.get("percent", body.get("usage_pct", 0)):.1f}%'
            elif event == "pids":
                return str(body.get("current", body.get("count", 0)))
            elif event == "pressure":
                return f'some={body.get("some_avg10", 0):.1f}%'
            return ""
        elif cat == "guard":
            ip = body.get("ip", body.get("source", ""))
            reason = body.get("reason", "")
            return f"{ip} ({reason})" if reason else ip
        elif cat == "firewall":
            return body.get("src", body.get("prefix", ""))
        elif cat == "conntrack":
            src = body.get("src", "")
            dst = body.get("dst", "")
            sport = body.get("sport", "")
            dport = body.get("dport", "")
            proto = body.get("proto", "")
            src_str = f"{src}:{sport}" if sport else src
            dst_str = f"{dst}:{dport}" if dport else dst
            return f"{proto} {src_str} → {dst_str}" if src else ""
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
        self.queue = queue  # list used as queue
        self._log_channels = {}  # {container_name: pika.Channel}
        self._log_queues = {}
        self._conn = None
        self._channel = None

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        while True:
            try:
                creds = pika.PlainCredentials("erlkoenig", "erlkoenig")
                params = pika.ConnectionParameters(
                    host=self.host, port=5672, credentials=creds,
                    heartbeat=30,
                )
                self._conn = pika.BlockingConnection(params)
                self._channel = self._conn.channel()

                # Events exchange
                self._channel.exchange_declare(
                    exchange=EXCHANGE, exchange_type="topic", durable=True
                )
                result = self._channel.queue_declare(queue="", exclusive=True)
                q = result.method.queue
                self._channel.queue_bind(
                    exchange=EXCHANGE, queue=q, routing_key="#"
                )
                self._channel.basic_consume(
                    queue=q, on_message_callback=self._on_event, auto_ack=True
                )
                self._channel.start_consuming()
            except Exception:
                self._conn = None
                self._channel = None
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
        """Start consuming log stream for a container in a new thread."""
        def _consume():
            try:
                creds = pika.PlainCredentials("erlkoenig", "erlkoenig")
                params = pika.ConnectionParameters(
                    host=self.host, port=5672, credentials=creds,
                    heartbeat=30,
                )
                conn = pika.BlockingConnection(params)
                ch = conn.channel()
                stream_name = f"{LOG_STREAM_PREFIX}{container_name}"
                is_stream = False

                # Try to consume from the stream
                try:
                    ch.queue_declare(
                        queue=stream_name, durable=True, passive=True
                    )
                    is_stream = True
                except Exception:
                    # Stream doesn't exist — try topic exchange fallback
                    conn = pika.BlockingConnection(params)
                    ch = conn.channel()
                    ch.exchange_declare(
                        exchange=EXCHANGE, exchange_type="topic", durable=True
                    )
                    result = ch.queue_declare(queue="", exclusive=True)
                    q = result.method.queue
                    ch.queue_bind(
                        exchange=EXCHANGE, queue=q,
                        routing_key=f"log.{container_name}.#"
                    )
                    stream_name = q

                def on_log(ch, method, props, body_bytes):
                    try:
                        headers = props.headers or {} if props.headers else {}
                        fd = headers.get("fd", "stdout")
                        if isinstance(body_bytes, bytes):
                            try:
                                text = body_bytes.decode("utf-8", errors="replace")
                            except Exception:
                                text = repr(body_bytes)
                        else:
                            text = str(body_bytes)
                        callback(container_name, fd, text)
                    except Exception:
                        pass

                # Streams require prefetch (QoS) before consuming
                if is_stream:
                    ch.basic_qos(prefetch_count=100)

                ch.basic_consume(
                    queue=stream_name,
                    on_message_callback=on_log,
                    auto_ack=not is_stream,
                    arguments={"x-stream-offset": "last"} if is_stream else {}
                )
                self._log_channels[container_name] = ch
                ch.start_consuming()
            except Exception as e:
                callback(container_name, "system",
                         f"[red]Could not attach to {container_name}: {e}[/]")

        t = threading.Thread(target=_consume, daemon=True)
        t.start()

    def replay_logs(self, container_name, callback):
        """Replay logs from the beginning of the stream."""
        def _consume():
            try:
                creds = pika.PlainCredentials("erlkoenig", "erlkoenig")
                params = pika.ConnectionParameters(
                    host=self.host, port=5672, credentials=creds,
                    heartbeat=30,
                )
                conn = pika.BlockingConnection(params)
                ch = conn.channel()
                stream_name = f"{LOG_STREAM_PREFIX}{container_name}"

                try:
                    ch.queue_declare(
                        queue=stream_name, durable=True, passive=True
                    )
                except Exception:
                    callback(container_name, "system",
                             f"[red]Stream {stream_name} not found[/]")
                    return

                def on_log(ch, method, props, body_bytes):
                    try:
                        headers = props.headers or {}
                        fd = headers.get("fd", "stdout")
                        ts = headers.get("wall_ts_ms", 0)
                        if ts:
                            ts_str = datetime.fromtimestamp(
                                ts / 1000).strftime("%H:%M:%S.%f")[:12]
                        else:
                            ts_str = ""
                        text = body_bytes.decode("utf-8", errors="replace")
                        callback(container_name, fd, text, ts_str)
                    except Exception:
                        pass

                # Streams require prefetch before consuming
                ch.basic_qos(prefetch_count=200)
                ch.basic_consume(
                    queue=stream_name,
                    on_message_callback=on_log,
                    auto_ack=False,
                    arguments={"x-stream-offset": "first"}
                )
                ch.start_consuming()
            except Exception as e:
                callback(container_name, "system",
                         f"[red]Replay failed: {e}[/]")

        t = threading.Thread(target=_consume, daemon=True)
        t.start()


# ═══════════════════════════════════════════════════════════
# Screens
# ═══════════════════════════════════════════════════════════

class HelpScreen(Screen):
    """Keybinding reference."""

    BINDINGS = [
        Binding("escape", "dismiss", "Back"),
        Binding("question_mark", "dismiss", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static("""[bold cyan]erlkoenig TUI — Keybindings[/]

[bold]Navigation[/]
  [green]1[/]           Dashboard (containers + stats + events)
  [green]2[/]           Full-screen event stream
  [green]3[/]           Log viewer (container stdout/stderr)

[bold]Container List[/]
  [green]j / k[/]       Move selection down / up
  [green]Enter[/]       Attach to selected container logs
  [green]i[/]           Show container detail

[bold]Log Viewer[/]
  [green]r[/]           Replay from beginning of stream
  [green]t[/]           Toggle timestamps
  [green]Escape[/]      Back to dashboard

[bold]Events[/]
  [green]f[/]           Filter events (e.g. 'container', 'firewall', 'stats')
  [green]c[/]           Clear event log

[bold]General[/]
  [green]?[/]           This help
  [green]q[/]           Quit
  [green]Escape[/]      Back / dismiss

[dim]Press Escape to close this help.[/]""",
                id="help-text"),
            id="help-container"
        )

    CSS = """
    #help-container {
        align: center middle;
        width: 70;
        height: auto;
        max-height: 80%;
        border: double cyan;
        padding: 1 2;
        background: $surface;
    }
    """


class LogScreen(Screen):
    """Full-screen log viewer for a single container."""

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("r", "replay", "Replay"),
        Binding("t", "toggle_ts", "Timestamps"),
        Binding("c", "clear", "Clear"),
    ]

    def __init__(self, container_name, amqp):
        super().__init__()
        self.container_name = container_name
        self.amqp = amqp
        self.show_ts = True
        self._log_queue = []
        self._lock = threading.Lock()

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(id="log-output", max_lines=2000, markup=True)
        yield Footer()

    def on_mount(self):
        self.title = f"logs: {self.container_name}"
        self.sub_title = "r=replay  t=timestamps  Esc=back"

        log = self.query_one("#log-output", RichLog)
        log.write(f"[dim]Attaching to {self.container_name}...[/]")

        self.amqp.attach_logs(self.container_name, self._on_log)
        self.set_interval(0.2, self._flush)

    def _on_log(self, name, fd, text, ts_str=None):
        with self._lock:
            self._log_queue.append((fd, text, ts_str))

    def _flush(self):
        with self._lock:
            items = list(self._log_queue)
            self._log_queue.clear()

        log = self.query_one("#log-output", RichLog)
        for fd, text, ts_str in items:
            for line in text.rstrip("\n").split("\n"):
                if not line:
                    continue
                if fd == "system":
                    log.write(line)
                    continue
                color = "white" if fd == "stdout" else "red"
                prefix = f"[dim]{fd}[/] "
                ts = f"[dim]{ts_str}[/] " if ts_str and self.show_ts else ""
                log.write(f"{ts}{prefix}[{color}]{line}[/]")

    def action_go_back(self):
        self.app.pop_screen()

    def action_replay(self):
        log = self.query_one("#log-output", RichLog)
        log.clear()
        log.write(f"[yellow]Replaying {self.container_name} from beginning...[/]")
        self.amqp.replay_logs(self.container_name, self._on_log)

    def action_toggle_ts(self):
        self.show_ts = not self.show_ts

    def action_clear(self):
        self.query_one("#log-output", RichLog).clear()


# ═══════════════════════════════════════════════════════════
# Main App
# ═══════════════════════════════════════════════════════════

class ErlkoenigTUI(App):
    """erlkoenig terminal user interface."""

    CSS = """
    Screen { layout: vertical; }

    #ct-table { height: auto; }

    #container-panel {
        height: auto;
        max-height: 45%;
        border: solid green;
        border-title-color: green;
    }
    #status-bar {
        height: 1;
        dock: bottom;
        background: $accent;
        color: $text;
        padding: 0 1;
    }
    #counter-panel {
        height: 3;
        border: solid yellow;
        border-title-color: yellow;
        padding: 0 1;
    }
    #event-panel {
        height: 1fr;
        min-height: 8;
        border: solid cyan;
        border-title-color: cyan;
    }
    #filter-input {
        dock: bottom;
        display: none;
        height: 3;
        border: solid magenta;
    }

    TabbedContent { height: 1fr; }
    TabPane { height: 1fr; padding: 0; }
    """

    TITLE = "erlkoenig"
    SUB_TITLE = "Speed and Control"

    BINDINGS = [
        Binding("question_mark", "help", "Help", key_display="?"),
        Binding("1", "view_dashboard", "Dashboard", key_display="1"),
        Binding("2", "view_events", "Events", key_display="2"),
        Binding("3", "view_logs", "Logs", key_display="3"),
        Binding("f", "filter", "Filter"),
        Binding("c", "clear_events", "Clear"),
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

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                yield DataTable(id="ct-table")
                yield Static(id="counter-panel")
                yield RichLog(id="event-log", max_lines=100, markup=True)
            with TabPane("Events", id="events-tab"):
                yield RichLog(id="event-full", max_lines=500, markup=True)
            with TabPane("Logs", id="logs-tab"):
                yield Static(
                    "[dim]Select a container from Dashboard (Enter) "
                    "or press [bold]3[/bold] then type a name.[/]\n\n"
                    "Available containers will appear once events arrive.",
                    id="log-placeholder"
                )
        yield Input(placeholder="Filter pattern (e.g. 'container', 'firewall')...",
                    id="filter-input")
        yield Footer()

    def on_mount(self):
        # Setup container table
        table = self.query_one("#ct-table", DataTable)
        table.add_columns(
            "CONTAINER", "STATE", "IP", "MEMORY", "CPU", "PIDs",
            "PSI", "RESTARTS", "SINCE"
        )
        table.cursor_type = "row"
        table.zebra_stripes = True

        self.query_one("#counter-panel").border_title = "firewall"

        # Start AMQP
        self._amqp = AmqpThread(
            self.amqp_host, self.state, self._lock, self._event_queue
        )
        self._amqp.start()

        # Refresh timer
        self.set_interval(0.5, self._tick)

    def _tick(self):
        with self._lock:
            new_events = list(self._event_queue)
            self._event_queue.clear()

        if new_events:
            self._refresh_table()
            self._refresh_counters()

        # Push events to logs (skip stats noise on dashboard)
        for _ in new_events:
            with self._lock:
                if not self.state.events:
                    continue
                ts, key, summary, cat = self.state.events[-1]

            # Stats only update the table, not the event stream
            if cat == "stats" and not self._filter:
                continue

            if self._filter and self._filter not in key:
                continue

            colors = {
                "container": "green", "stats": "blue",
                "firewall": "red", "guard": "yellow",
                "conntrack": "cyan", "system": "magenta",
                "security": "red", "control": "white",
            }
            color = colors.get(cat, "white")
            detail = f"  {summary}" if summary else ""
            line = f"[dim]{ts}[/]  [{color}]{key}[/]{detail}"

            try:
                self.query_one("#event-log", RichLog).write(line)
            except Exception:
                pass
            try:
                self.query_one("#event-full", RichLog).write(line)
            except Exception:
                pass

        # Update header
        n = len(self.state.containers)
        node = self.state.node
        self.sub_title = f"{node} — {n} containers"

    def _refresh_table(self):
        table = self.query_one("#ct-table", DataTable)
        # Remember cursor position
        try:
            cursor_row = table.cursor_row
        except Exception:
            cursor_row = 0

        table.clear()
        for name in sorted(self.state.containers.keys()):
            ct = self.state.containers[name]
            s = ct.get("state", "?")
            ip = ct.get("ip", "")
            mem = fmt_bytes(ct.get("mem_bytes", 0))
            cpu = f'{ct.get("cpu_pct", 0):.1f}%'
            pids = str(ct.get("pids", 0))
            psi = f'{ct.get("psi_some", 0):.1f}%' if ct.get("psi_some") else "-"
            restarts = str(ct.get("restarts", 0))
            since = ct.get("started_at", "")

            state_map = {
                "running": "[green]● run[/]",
                "stopped": "[dim]○ stop[/]",
                "oom": "[red]✗ oom[/]",
                "failed": "[red]✗ fail[/]",
            }
            state_str = state_map.get(s, f"[yellow]? {s}[/]")
            table.add_row(name, state_str, ip, mem, cpu, pids, psi, restarts, since)

        # Restore cursor
        if cursor_row < table.row_count:
            table.move_cursor(row=cursor_row)

    def _refresh_counters(self):
        parts = []
        for k, v in sorted(self.state.counters.items()):
            parts.append(f"[bold]{k}[/]: {v}")
        if not parts:
            parts.append("[dim]no drops[/]")
        extra = (
            f"  [dim]│[/]  banned: [red]{self.state.banned}[/]"
            f"  [dim]│[/]  flows: {self.state.flows}"
        )
        try:
            self.query_one("#counter-panel", Static).update(
                "  ".join(parts) + extra
            )
        except Exception:
            pass

    # ── Actions ──────────────────────────────────

    def action_help(self):
        self.push_screen(HelpScreen())

    def action_view_dashboard(self):
        self.query_one(TabbedContent).active = "dashboard"

    def action_view_events(self):
        self.query_one(TabbedContent).active = "events-tab"

    def action_view_logs(self):
        # Get selected container from table
        table = self.query_one("#ct-table", DataTable)
        if table.row_count == 0:
            self.notify("No containers available", severity="warning")
            return
        try:
            row = table.get_row_at(table.cursor_row)
            name = row[0]
        except Exception:
            name = None

        if name and name in self.state.containers:
            self.push_screen(LogScreen(name, self._amqp))
        else:
            self.notify("Select a container first (j/k + Enter)", severity="warning")

    def action_filter(self):
        inp = self.query_one("#filter-input", Input)
        inp.display = True
        inp.focus()

    def on_input_submitted(self, event: Input.Submitted):
        inp = self.query_one("#filter-input", Input)
        self._filter = inp.value.strip()
        inp.display = False
        if self._filter:
            self.notify(f"Filter: {self._filter}")
        else:
            self.notify("Filter cleared")

    def action_clear_events(self):
        try:
            self.query_one("#event-log", RichLog).clear()
        except Exception:
            pass
        try:
            self.query_one("#event-full", RichLog).clear()
        except Exception:
            pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        """Enter on a container row → open log view."""
        row = event.data_table.get_row(event.row_key)
        name = row[0]
        if name in self.state.containers:
            self.push_screen(LogScreen(name, self._amqp))


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    app = ErlkoenigTUI(host=host)
    app.run()


if __name__ == "__main__":
    main()
