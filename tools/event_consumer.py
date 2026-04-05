#!/usr/bin/env python3
"""erlkoenig event consumer — demo tool, not production code.

Usage:
    python3 event_consumer.py                          # localhost, container.*
    python3 event_consumer.py erlkoenig-2              # remote host
    python3 event_consumer.py localhost "#"             # all events
    python3 event_consumer.py localhost "policy.*"      # policy events only

Requires: pip install pika
"""
import pika
import json
import sys


def on_message(ch, method, properties, body):
    try:
        event = json.loads(body)
    except json.JSONDecodeError:
        print(f"[?] raw: {body[:100]}")
        ch.basic_ack(method.delivery_tag)
        return

    rk = event.get("routing_key", method.routing_key)
    payload = event.get("payload", {})
    cid = payload.get("name", payload.get("id", "?"))
    if len(cid) > 36:
        cid = cid[:36]
    ts = event.get("ts", "")[11:23]  # HH:MM:SS.mmm

    detail = ""
    # nft counter drops (most common, check first)
    if rk.startswith("nft.counter.") and "packets" in payload:
        pps = payload.get("pps", 0)
        detail = f" {payload['packets']} pkts ({pps:.0f} pps)"
    # container lifecycle
    elif "exit_code" in payload:
        detail = f" exit={payload['exit_code']} sig={payload['signal']}"
    elif "attempt" in payload:
        detail = f" attempt #{payload['attempt']}"
    elif "failures" in payload:
        detail = f" failures={payload['failures']}"
    elif "violation_type" in payload:
        detail = f" {payload['violation_type']} action={payload.get('action', '?')}"
    # nft guard
    elif rk.startswith("nft.guard.ban"):
        detail = f" {payload.get('reason', '?')} duration={payload.get('duration', '?')}s"
    # nft control
    elif "action" in payload and "status" in payload:
        detail = f" {payload['action']} {payload['status']}"
        d = payload.get("details", {})
        if "ip" in d:
            detail += f" ip={d['ip']}"
    # nft threshold
    elif "threshold" in payload:
        detail = f" {payload.get('metric', '?')}={payload.get('current', '?')}/{payload['threshold']}"
    # metrics
    elif "type" in payload and rk.startswith("metrics."):
        detail = f" {payload['type']}"
        if "comm" in payload:
            detail += f" comm={payload['comm']}"
    # fallback
    elif "reason" in payload:
        detail = f" {payload['reason']}"

    # Build subject line
    subject = cid
    if cid == "?":
        if (rk.startswith("nft.ct.") or rk.startswith("nft.drop.") or rk.startswith("nft.nflog")) and "src" in payload:
            src = payload.get("src", "?")
            dst = payload.get("dst", "?")
            proto = payload.get("proto", "")
            sport = payload.get("sport", "")
            dport = payload.get("dport", "")
            detail = f" {proto} {src}:{sport} → {dst}:{dport}"
            subject = ""
        elif rk == "nft.guard.ban":
            subject = payload.get("ip", "?")
            detail = f" {payload.get('reason', '?')} duration={payload.get('duration', '?')}s"
        elif rk.startswith("nft.counter."):
            subject = payload.get("name", rk.split(".")[-1])
        elif "action" in payload and "status" in payload:
            subject = payload["action"][:12]
            d = payload.get("details", {})
            if "ip" in d:
                detail = f" {payload['status']} ip={d['ip']}"
        elif "name" in payload:
            subject = str(payload["name"])[:12]

    print(f"{ts} {rk:35s} {subject}{detail}")
    ch.basic_ack(method.delivery_tag)


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    pattern = sys.argv[2] if len(sys.argv) > 2 else "container.*"

    conn = pika.BlockingConnection(pika.ConnectionParameters(host))
    ch = conn.channel()
    ch.exchange_declare("erlkoenig.events", "topic", durable=True)
    q = ch.queue_declare("", exclusive=True)
    ch.queue_bind(q.method.queue, "erlkoenig.events", pattern)
    print(f"Listening on {host} exchange=erlkoenig.events pattern={pattern}")
    print("─" * 60)

    try:
        ch.basic_consume(q.method.queue, on_message)
        ch.start_consuming()
    except KeyboardInterrupt:
        print("\nBye.")
        conn.close()


if __name__ == "__main__":
    main()
