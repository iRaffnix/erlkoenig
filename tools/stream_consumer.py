#!/usr/bin/env python3
"""erlkoenig stream log consumer — reads container stdout/stderr from RabbitMQ Streams.

Usage:
    python3 stream_consumer.py <stream-name>                    # from beginning
    python3 stream_consumer.py <stream-name> --last 100         # last 100 messages
    python3 stream_consumer.py <stream-name> --offset next      # only new messages

Examples:
    python3 stream_consumer.py erlkoenig.log.web-0-nginx
    python3 stream_consumer.py erlkoenig.log.web-0-nginx --filter stderr
    python3 stream_consumer.py erlkoenig.log.web-0-nginx --last 50

Requires: pip install pika
"""
import pika
import sys
import os

HOST = os.environ.get("AMQP_HOST", "10.20.30.2")
USER = os.environ.get("AMQP_USER", "erlkoenig")
PASS = os.environ.get("AMQP_PASS", "erlkoenig")

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

def c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

DIM = lambda t: c("2", t)
GREEN = lambda t: c("32", t)
YELLOW = lambda t: c("33", t)
RED = lambda t: c("31", t)
CYAN = lambda t: c("36", t)


def on_message(ch, method, properties, body):
    headers = properties.headers or {}
    fd = headers.get("fd", b"?")
    if isinstance(fd, bytes):
        fd = fd.decode()
    name = headers.get("name", b"?")
    if isinstance(name, bytes):
        name = name.decode()
    seq = headers.get("seq", "?")
    boot = headers.get("boot", 0)
    wall_ts = headers.get("wall_ts_ms", 0)
    instance = headers.get("instance", b"?")
    if isinstance(instance, bytes):
        instance = instance.decode()

    # Apply filter
    if FILTER and fd != FILTER:
        ch.basic_ack(method.delivery_tag)
        return

    # Format timestamp
    if wall_ts and isinstance(wall_ts, int):
        import datetime
        ts = datetime.datetime.fromtimestamp(wall_ts / 1000).strftime("%H:%M:%S.%f")[:-3]
    else:
        ts = "??:??:??"

    # Format output
    tag = RED("ERR") if fd == "stderr" else DIM("OUT")
    data = body.decode("utf-8", errors="replace").rstrip("\n")

    for line in data.split("\n"):
        print(f"{DIM(ts)} {CYAN(f'{name}'):>20s} {tag} [{seq}] {line}")

    ch.basic_ack(method.delivery_tag)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    stream_name = sys.argv[1]

    # Parse options
    global FILTER
    FILTER = None
    offset = "first"

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--filter" and i + 1 < len(sys.argv):
            FILTER = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--last" and i + 1 < len(sys.argv):
            offset = f"last"
            last_n = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--offset" and i + 1 < len(sys.argv):
            offset = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    creds = pika.PlainCredentials(USER, PASS)
    conn = pika.BlockingConnection(pika.ConnectionParameters(HOST, credentials=creds))
    ch = conn.channel()

    # Consume from the stream queue
    # x-stream-offset tells RabbitMQ where to start reading
    consumer_args = {"x-stream-offset": offset}

    if FILTER:
        consumer_args["x-stream-filter"] = FILTER

    print(f"Stream: {stream_name}")
    print(f"Offset: {offset}")
    if FILTER:
        print(f"Filter: {FILTER}")
    print("-" * 60)

    try:
        ch.basic_qos(prefetch_count=100)
        ch.basic_consume(
            queue=stream_name,
            on_message_callback=on_message,
            arguments=consumer_args
        )
        ch.start_consuming()
    except KeyboardInterrupt:
        print("\nBye.")
        conn.close()
    except pika.exceptions.ChannelClosedByBroker as e:
        print(f"Error: {e}")
        print(f"Stream '{stream_name}' may not exist yet.")


if __name__ == "__main__":
    main()
