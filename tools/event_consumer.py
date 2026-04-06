#!/usr/bin/env python3
"""erlkoenig event consumer — demo tool, not production code.

Usage:
    python3 event_consumer.py                                   # localhost, all events
    python3 event_consumer.py erlkoenig-2                       # remote host
    python3 event_consumer.py localhost "container.#"            # container lifecycle
    python3 event_consumer.py localhost "stats.web-0-nginx.*"    # stats for one container
    python3 event_consumer.py localhost "firewall.#"             # firewall events
    python3 event_consumer.py localhost "guard.#"                # guard ban/unban

Options (env vars):
    HIDE_LOCAL=1     Hide 127.0.0.1 conntrack events
    NO_COLOR=1       Disable ANSI colors

Routing key schema (v2):
    container.<name>.<event>      — started, stopped, failed, restarting, oom, health
    stats.<name>.<metric>         — memory, cpu, pids, pressure, oom
    firewall.<chain>.<event>      — drop, packet
    conntrack.flow.<event>        — new, destroy
    conntrack.alert.mode          — mode switch
    guard.threat.<event>          — ban, unban
    control.<scope>.<action>      — nft/set operations
    policy.<name>.violation       — policy violations

Requires: pip install pika
"""
import pika
import json
import sys
import os
from collections import defaultdict

# ── Colors ──────────────────────────────────────────────────
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
HIDE_LOCAL = os.environ.get("HIDE_LOCAL", "1") == "1"

def c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

DIM    = lambda t: c("2", t)
GREEN  = lambda t: c("32", t)
YELLOW = lambda t: c("33", t)
RED    = lambda t: c("31", t)
CYAN   = lambda t: c("36", t)
BOLD   = lambda t: c("1", t)
BLUE   = lambda t: c("34", t)
MAG    = lambda t: c("35", t)

# ── Stats aggregator ────────────────────────────────────────
# Collects memory/cpu/pids for the same container+timestamp
# and prints one compact line instead of three.

stats_buf = defaultdict(dict)  # key: (name, ts_sec) -> {metric: payload}
last_flush_ts = {}             # key: name -> last ts_sec flushed


def buffer_stat(name, metric, payload, ts):
    ts_sec = ts[:8]  # HH:MM:SS (group by second)
    key = (name, ts_sec)
    stats_buf[key][metric] = payload

    # Flush when we have all fast metrics or both slow metrics
    metrics = stats_buf[key]
    fast_complete = "memory" in metrics and "cpu" in metrics and "pids" in metrics
    slow_complete = "pressure" in metrics and "oom" in metrics

    if fast_complete or slow_complete:
        flush_stats(name, ts_sec, metrics)
        del stats_buf[key]


def flush_stats(name, ts_sec, metrics):
    parts = []

    if "memory" in metrics:
        m = metrics["memory"]
        cur = fmt_bytes(m.get("current", 0))
        pct = m.get("pct", 0)
        peak = fmt_bytes(m.get("peak", 0))
        swap = m.get("swap", 0)
        mem_str = f"mem={cur}"
        if pct > 0:
            mem_str += f"({pct}%)"
        mem_str += f" peak={peak}"
        if swap > 0:
            mem_str += f" swap={fmt_bytes(swap)}"
        parts.append(mem_str)

    if "cpu" in metrics:
        cp = metrics["cpu"]
        delta = cp.get("delta_usec", 0)
        throttled = cp.get("throttled_usec", 0)
        cpu_str = f"cpu={delta}us"
        if throttled > 0:
            cpu_str += f" thr={throttled}us"
        parts.append(cpu_str)

    if "pids" in metrics:
        p = metrics["pids"]
        cur = p.get("current", 0)
        mx = p.get("max", "max")
        parts.append(f"pids={cur}/{mx}")

    if "pressure" in metrics:
        pr = metrics["pressure"]
        cpu_p = pr.get("cpu_some_avg10", 0.0)
        mem_p = pr.get("memory_some_avg10", 0.0)
        io_p = pr.get("io_some_avg10", 0.0)
        # Only show non-zero pressure
        psi_parts = []
        if cpu_p > 0:
            psi_parts.append(f"cpu={cpu_p}%")
        if mem_p > 0:
            psi_parts.append(f"mem={mem_p}%")
        if io_p > 0:
            psi_parts.append(f"io={io_p}%")
        if psi_parts:
            parts.append("psi:" + ",".join(psi_parts))
        else:
            parts.append("psi:ok")

    if "oom" in metrics:
        om = metrics["oom"]
        kills = om.get("kills", 0)
        if kills > 0:
            parts.append(RED(f"oom_kill={kills}"))
        else:
            parts.append("oom:ok")

    line = " ".join(parts)
    label = CYAN(f"{name:>20s}")
    print(f"{DIM(ts_sec)}     {label}  {line}")


# ── Message handler ─────────────────────────────────────────

def on_message(ch, method, properties, body):
    try:
        event = json.loads(body)
    except json.JSONDecodeError:
        print(f"[?] raw: {body[:100]}")
        ch.basic_ack(method.delivery_tag)
        return

    rk = event.get("key", method.routing_key)
    payload = event.get("payload", {})
    ts = event.get("ts", "")[11:23]  # HH:MM:SS.mmm

    # ── Stats: buffer and aggregate ──
    if rk.startswith("stats."):
        parts = rk.split(".")
        if len(parts) == 3:
            name, metric = parts[1], parts[2]
            buffer_stat(name, metric, payload, ts)
            ch.basic_ack(method.delivery_tag)
            return

    # ── Conntrack: filter localhost noise ──
    if rk.startswith("conntrack.") and HIDE_LOCAL:
        src = payload.get("src", "")
        if src == "127.0.0.1":
            ch.basic_ack(method.delivery_tag)
            return

    # ── Format single-line events ──
    ts_short = DIM(ts[:8])
    detail = format_event(rk, payload)
    if detail is not None:
        print(f"{ts_short}     {detail}")

    ch.basic_ack(method.delivery_tag)


def format_event(rk, payload):
    # Container lifecycle
    if rk.startswith("container."):
        name = payload.get("name", "?")
        label = BOLD(GREEN(f"{name:>20s}"))
        if rk.endswith(".started"):
            pid = payload.get("os_pid", "?")
            return f"{label}  {GREEN('STARTED')} pid={pid}"
        if rk.endswith(".stopped"):
            code = payload.get("exit_code", "?")
            sig = payload.get("signal", "?")
            return f"{label}  {YELLOW('STOPPED')} exit={code} sig={sig}"
        if rk.endswith(".failed"):
            reason = payload.get("reason", "?")
            return f"{label}  {RED('FAILED')} {reason}"
        if rk.endswith(".restarting"):
            attempt = payload.get("attempt", "?")
            return f"{label}  {YELLOW('RESTART')} attempt #{attempt}"
        if rk.endswith(".oom"):
            return f"{label}  {RED('OOM KILLED')}"
        if rk.endswith(".health"):
            fails = payload.get("failures", "?")
            return f"{label}  {YELLOW('UNHEALTHY')} failures={fails}"
        return f"{label}  {rk.split('.')[-1]}"

    # Firewall
    if rk.startswith("firewall."):
        chain = rk.split(".")[1]
        label = MAG(f"{chain:>20s}")
        if rk.endswith(".drop"):
            pkts = payload.get("packets", 0)
            pps = payload.get("pps", 0)
            bps = payload.get("bps", 0)
            return f"{label}  {RED('DROP')} {pkts} pkts ({pps:.0f} pps, {fmt_bytes(bps)}/s)"
        if rk.endswith(".packet"):
            src = payload.get("src", "?")
            dst = payload.get("dst", "?")
            proto = payload.get("proto", "?")
            sport = payload.get("sport", "")
            dport = payload.get("dport", "")
            return f"{label}  {RED('PKT')}  {proto} {src}:{sport} -> {dst}:{dport}"
        return f"{label}  {rk.split('.')[-1]}"

    # Conntrack
    if rk.startswith("conntrack."):
        src = payload.get("src", "?")
        dst = payload.get("dst", "?")
        proto = payload.get("proto", "?")
        sport = payload.get("sport", "")
        dport = payload.get("dport", "")
        event_type = rk.split(".")[-1]
        tag = GREEN("NEW") if event_type == "new" else DIM("END")
        flow = f"{proto} {src}:{sport} -> {dst}:{dport}"
        return f"{DIM('conntrack'):>20s}  {tag}  {flow}"

    # Guard
    if rk.startswith("guard."):
        ip = payload.get("ip", "?")
        if rk.endswith(".ban"):
            reason = payload.get("reason", "?")
            dur = payload.get("duration", "?")
            return f"{RED('GUARD'):>20s}  {RED('BAN')} {ip} reason={reason} duration={dur}s"
        if rk.endswith(".unban"):
            return f"{YELLOW('GUARD'):>20s}  UNBAN {ip}"
        return None

    # Control
    if rk.startswith("control."):
        action = payload.get("action", "?")
        status = payload.get("status", "?")
        details = payload.get("details", {})
        ip = details.get("ip", "")
        extra = f" ip={ip}" if ip else ""
        return f"{BLUE('control'):>20s}  {action} {status}{extra}"

    # Policy
    if rk.startswith("policy."):
        name = rk.split(".")[1]
        vtype = payload.get("violation_type", "?")
        action = payload.get("action", "?")
        return f"{RED(f'{name:>20s}')}  POLICY {vtype} action={action}"

    # Metrics (BPF: fork/exec/exit/oom)
    if rk.startswith("metrics."):
        name = payload.get("name", rk.split(".")[1])
        mtype = payload.get("type", "?")
        comm = payload.get("comm", "")
        extra = f" comm={comm}" if comm else ""
        return f"{CYAN(f'{name:>20s}')}  {mtype}{extra}"

    # System
    if rk.startswith("system."):
        if rk.endswith(".loaded"):
            pods = payload.get("pods", 0)
            zones = payload.get("zones", 0)
            return f"{BLUE('system'):>20s}  CONFIG LOADED pods={pods} zones={zones}"
        if rk.endswith(".failed"):
            reason = payload.get("reason", "?")
            return f"{BLUE('system'):>20s}  {RED('CONFIG FAILED')} {reason}"
        if rk.endswith(".applied"):
            table = payload.get("table", "?")
            return f"{BLUE('system'):>20s}  FIREWALL APPLIED {table}"
        if rk.endswith("firewall.failed"):
            table = payload.get("table", "?")
            return f"{BLUE('system'):>20s}  {RED('FIREWALL FAILED')} {table}"
        return f"{BLUE('system'):>20s}  {rk}"

    # Security
    if rk.startswith("security."):
        name = rk.split(".")[1]
        if rk.endswith(".verified"):
            signer = payload.get("signer", "?")
            return f"{GREEN(f'{name:>20s}')}  {GREEN('SIG OK')} signer={signer}"
        if rk.endswith(".rejected"):
            reason = payload.get("reason", "?")
            return f"{RED(f'{name:>20s}')}  {RED('SIG REJECTED')} {reason}"
        return None

    # Unknown
    return f"{'?':>20s}  {rk}"


def fmt_bytes(n):
    if not isinstance(n, (int, float)):
        return str(n)
    if n >= 1_073_741_824:
        return f"{n / 1_073_741_824:.1f}G"
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f}M"
    if n >= 1024:
        return f"{n / 1024:.1f}K"
    return f"{n}B"


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    pattern = sys.argv[2] if len(sys.argv) > 2 else "#"
    user = os.environ.get("AMQP_USER", "erlkoenig")
    passwd = os.environ.get("AMQP_PASS", "erlkoenig")

    creds = pika.PlainCredentials(user, passwd)
    params = pika.ConnectionParameters(host, credentials=creds)
    conn = pika.BlockingConnection(params)
    ch = conn.channel()
    ch.exchange_declare("erlkoenig.events", "topic", durable=True)
    q = ch.queue_declare("", exclusive=True)
    ch.queue_bind(q.method.queue, "erlkoenig.events", pattern)

    hide = " (hiding localhost)" if HIDE_LOCAL else ""
    print(f"Listening on {host} pattern={pattern}{hide}")
    print("-" * 70)

    try:
        ch.basic_consume(q.method.queue, on_message)
        ch.start_consuming()
    except KeyboardInterrupt:
        print("\nBye.")
        conn.close()


if __name__ == "__main__":
    main()
