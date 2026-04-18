# Chapter 11 — Logging

Container stdout and stderr are first-class outputs. Each container
can ship its output to a dedicated RabbitMQ stream, tagged with the
container name, replica instance, and file descriptor. Streams are
append-only, retention is configurable, and consumers read at their
own pace — the container never blocks on a slow downstream.

## The streaming model

A container's output is captured by the BEAM over the Unix socket
that already connects it to the C runtime. `erlkoenig_log_publisher`
reads raw bytes, splits them into chunks, and publishes each chunk
as an AMQP message onto a RabbitMQ stream named
`erlkoenig.log.<container>`. Streams are a dedicated RabbitMQ
message type designed for append-only workloads — high-volume,
long-retention, offset-based replay.

Without a `stream` block in the DSL, no streaming happens. The
container runs normally; its stdout/stderr are simply discarded
(they still flow through the Erlang port, they're just not
forwarded to a stream).

## The `stream` block

A container opts in by declaring:

```elixir
container "api", binary: "...", zone: "dmz",
  replicas: 1, restart: :permanent do

  stream retention: {30, :days}, max_bytes: {5, :gb} do
    channel :stdout
    channel :stderr
  end
end
```

Options:

| Option        | Type                | Default       | Meaning                                    |
|---------------|---------------------|---------------|--------------------------------------------|
| `retention:`  | `{N, :days}` etc.   | `{7, :days}`  | How long the stream holds messages         |
| `max_bytes:`  | `{N, :gb/:mb}`      | unlimited     | Optional size cap                          |

Channels inside the block enable forwarding per file descriptor.
`channel :stdout` and `channel :stderr` are the two valid options;
both can be enabled, and both end up in the *same* stream —
distinguished by message headers, not by separate routing keys.

## Message shape

Each chunk becomes one AMQP message. Headers carry the metadata:

| Header        | Example          | Meaning                                        |
|---------------|------------------|------------------------------------------------|
| `fd`          | `"stdout"` / `"stderr"` | Which file descriptor the chunk came from |
| `name`        | `"web-0-api"`    | Container name                                 |
| `node`        | `"ek@host1"`     | Erlang node that published the chunk           |
| `instance`    | `"a1b2c3d4"`     | UUID prefix unique per spawn                   |
| `seq`         | `42`             | Monotonic sequence within an instance          |
| `boot`        | `1`              | Restart counter                                |
| `wall_ts_ms`  | `1712412182456`  | Wall-clock timestamp in milliseconds           |

The body is the raw bytes — no framing, no encoding, no size prefix.
A consumer that wants line boundaries reassembles them itself, which
is exactly what standard tooling expects.

## Routing key format

The AMQP routing key follows `erlkoenig.log.<pod>-<replica>-<container>`.
For a pod `web` with two replicas of container `api`, the two
streams are `erlkoenig.log.web-0-api` and `erlkoenig.log.web-1-api`.
Different replicas, different streams — a replica-specific view is a
straightforward subscription.

To separate stdout from stderr, a consumer filters on the `fd`
header. Server-side Bloom filtering exists via
`x-stream-filter-value`, but it's approximate; client-side
filtering on the header is exact.

## Backpressure

The container's file descriptors must never block on AMQP slowness.
Three layers of protection guarantee that:

1. **In-flight high-water mark.** An atomic counter tracks chunks
   waiting to be published. Above 2000, new chunks are dropped at
   the source.
2. **Bounded queue.** A per-container queue of 1000 chunks feeds the
   publisher. When full, the oldest chunks are dropped to make room
   for new ones.
3. **Drop accounting.** Every dropped chunk increments a counter
   surfaced as a `system.log.overflow` event (→ Chapter 9) with
   chunk count and byte count.

Container I/O never blocks. Downstream slowness becomes visible as
drops, which become visible as events. Operators see slowdowns
explicitly rather than experiencing silent container stalls.

## Consuming streams

The Python helper `tools/stream_consumer.py` is a basic subscriber:
connect to a broker, open a stream, print every message. For
production log ingestion, any RabbitMQ-stream-aware client works —
standard options include offset-based replay (start from a specific
point in the stream), server-side filtering by routing key, and
message reading in batches.

Forensic queries against older messages use the stream's offset as
a time cursor: every message carries its `wall_ts_ms`, which
approximately maps onto broker arrival time. Consumers that need
exact wall-clock ordering read by offset and group by timestamp
client-side.

## Hands-on: stream a container's stdout

Start a container with stream forwarding enabled, consume its output
from the broker, and induce backpressure to see the drop accounting.

**1. Stack with streaming enabled.** Save as `~/log_demo.exs`:

```elixir
defmodule LogDemo do
  use Erlkoenig.Stack

  host do
    ipvlan "l", parent: {:dummy, "ek_l"}, subnet: {10, 112, 0, 0, 24}
  end

  pod "lg", strategy: :one_for_one do
    container "chatty",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9000"],
      zone: "l",
      replicas: 1,
      restart: :permanent do

      stream retention: {1, :days}, max_bytes: {100, :mb} do
        channel :stdout
        channel :stderr
      end
    end
  end
end
```

```bash
ek dsl compile ~/log_demo.exs -o /tmp/log.term
ek up /tmp/log.term
```

**2. Consume the stream.** Requires RabbitMQ broker reachable at
`amqp://erlkoenig@localhost`:

```bash
tools/stream_consumer.py amqp://erlkoenig@localhost \
    erlkoenig.log.lg-0-chatty --follow
```

Expected output:

    [2026-04-17T13:04:12Z stdout seq=1] hello from echo_server
    [2026-04-17T13:04:12Z stdout seq=2] listening on 9000
    [2026-04-17T13:04:15Z stderr seq=3] warning: using default config
    ...

**3. Filter stdout vs stderr client-side.**

```bash
tools/stream_consumer.py amqp://... erlkoenig.log.lg-0-chatty \
    --fd stderr
```

The `--fd` flag filters on the `fd` header. Server-side Bloom
filtering (`x-stream-filter-value`) is an optimisation; the header
match is exact.

**4. Offset-based replay.** Every chunk has an offset. Read the last
100 messages:

```bash
tools/stream_consumer.py amqp://... erlkoenig.log.lg-0-chatty \
    --offset last-100
```

Or replay from a specific wall-clock approximation — the stream
consumer searches by `wall_ts_ms` header:

```bash
tools/stream_consumer.py amqp://... erlkoenig.log.lg-0-chatty \
    --since '2026-04-17T13:00:00Z'
```

**5. Induce backpressure.** Kill the broker or suspend the consumer
to back up the queue. The erlkoenig side keeps publishing until the
per-container queue (1000 chunks) fills, then drops oldest chunks:

```bash
# Pause all incoming on the broker — simulate slow downstream
rabbitmqctl stop_app

# Watch the bus on another terminal for overflow events
tools/event_consumer.py amqp://... 'system.log.overflow'
```

Resume and read the overflow accounting:

    system.log.overflow    { name: "lg-0-chatty",
                              dropped_count: 247,
                              dropped_bytes: 124518 }

Container I/O never blocks — `write()` on the container's stdout
fd proceeds at full speed. Drops are accounted for but the
application doesn't know; this is deliberate.

**6. Multi-replica separation.** With `replicas: 3`, the streams
are `erlkoenig.log.lg-0-chatty`, `erlkoenig.log.lg-1-chatty`,
`erlkoenig.log.lg-2-chatty`. A consumer interested in a single
replica subscribes to one stream name; a consumer interested in all
replicas opens three subscriptions or uses a broker-side topic
binding.

**7. Tear down.**

```bash
ek down /tmp/log.term
```

The stream itself (RabbitMQ resource) is not deleted — retention
determines when the data ages out. A subsequent `ek up` with the
same container name would re-attach to the same stream and continue
appending after the last offset.
