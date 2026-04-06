# Container Log Streaming

Container stdout and stderr can be streamed to RabbitMQ Streams —
append-only logs with offset-based replay and configurable retention.

## How It Works

```
Container Process
  │ stdout/stderr pipes
  ▼
erlkoenig_rt (C Runtime, Unix Socket)
  ▼
erlkoenig_ct (gen_statem)
  │ forward_output/3
  │ atomics high-watermark check
  ▼
erlkoenig_log_publisher (gen_server)
  │ buffer → bounded queue → drain
  ▼
RabbitMQ Stream
  erlkoenig.log.<container-name>
```

One stream per container. stdout and stderr land in the same stream,
distinguished by a `headers.fd` field. This preserves the exact
interleaving order of both channels.

## DSL Configuration

Streaming is opt-in per container:

```elixir
pod "web", strategy: :one_for_one do
  container "api",
    binary: "/opt/api",
    args: ["--port", "4000"],
    restart: :always do

    # cgroup metrics (existing)
    publish interval: 5000 do
      metric :memory
      metric :cpu
    end

    # log streaming (new)
    stream retention: {90, :days} do
      channel :stdout
      channel :stderr
    end
  end
end
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `retention:` | `{integer, :days}` | `{7, :days}` | How long data stays in the stream |
| `max_bytes:` | `{number, :gb \\| :mb}` | unlimited | Optional size cap |

### Channels

- `channel :stdout` — stream container stdout
- `channel :stderr` — stream container stderr

Both channels land in the **same** stream. Retention is a stream-level
property — both channels share it.

Without a `stream` block, no streaming occurs (zero overhead).

## Stream Names

```
erlkoenig.log.<container-name>

erlkoenig.log.echo-0-echo       pod "echo", replica 0, container "echo"
erlkoenig.log.web-0-nginx       pod "web",  replica 0, container "nginx"
erlkoenig.log.web-1-nginx       pod "web",  replica 1, container "nginx"
```

Streams persist independently of containers. When a container stops,
the stream remains until retention expires. When a container restarts,
new output appends to the same stream.

## Message Format

The message body contains **raw bytes** from the container — no JSON
wrapping, no encoding. Metadata lives in AMQP message properties:

| Header | Example | Description |
|--------|---------|-------------|
| `fd` | `"stderr"` | File descriptor: `stdout` or `stderr` |
| `name` | `"web-0-nginx"` | Container name |
| `node` | `"erlkoenig@worker-1"` | Erlang node |
| `instance` | `"a1b2c3d4"` | Container UUID prefix (unique per spawn) |
| `seq` | `42` | Monotone sequence per incarnation |
| `boot` | `1` | Restart count within BEAM session |
| `wall_ts_ms` | `1712412182456` | UTC wallclock (milliseconds) |
| `eof` | `true` | Last chunk before container stop (optional) |

## Consuming Logs

### Python Stream Consumer

```bash
# All logs from beginning
python3 tools/stream_consumer.py erlkoenig.log.web-0-nginx

# Only stderr
python3 tools/stream_consumer.py erlkoenig.log.web-0-nginx --filter stderr

# Only new messages
python3 tools/stream_consumer.py erlkoenig.log.web-0-nginx --offset next
```

Sample output:

```
15:53:56.781 echo-0-echo ERR [0] echo: listening on port 7777
15:57:05.376 echo-0-echo ERR [1] echo: client connected
15:57:05.376 echo-0-echo ERR [2] echo: client disconnected
15:58:30.555 echo-0-echo ERR [0] echo: listening on port 7777  ← new incarnation
```

### Forensic Replay

Streams support offset-based replay. A consumer can attach at any
offset or approximate timestamp and read forward:

```python
# Replay from a specific offset
ch.basic_consume(
    queue="erlkoenig.log.web-0-nginx",
    arguments={"x-stream-offset": 42}  # exact offset
)

# Replay from approximate time
ch.basic_consume(
    queue="erlkoenig.log.web-0-nginx",
    arguments={"x-stream-offset": timestamp(2026, 4, 6, 14, 23)}
)
```

Timestamp-based attach uses broker arrival time (second-granularity,
chunk-aligned). For exact reconstruction, use `headers.seq`.

### Server-Side Filtering

When publishing, `x-stream-filter-value` is set to `"stdout"` or
`"stderr"`. Consumers can use `x-stream-filter` for Bloom-filter-based
server-side filtering — reduces traffic but not exact (false positives
possible). Use `headers.fd` for precise client-side filtering.

## Correlated Timeline

Log streams complement the existing AMQP event bridge. Together they
form a correlated observability model:

| Category | Transport | Storage |
|----------|-----------|---------|
| Metrics + Events | AMQP Topic Exchange | Transient |
| Container Logs | RabbitMQ Streams | Append-Only |

Both share the same schema (name, node, timestamps) and can be
correlated by timestamp:

```
14:23:00  stats.web-0-nginx.memory    mem=256MB (48%)
14:23:00  log.web-0-nginx.stdout      "Processing request from 10.0.0.5"
14:23:01  log.web-0-nginx.stderr      "ERROR: DB connection timeout"
14:23:01  conntrack.flow.new          tcp 10.0.0.5:54321 → 10.0.2.2:5432
14:23:02  guard.threat.ban            10.0.0.5 reason=conn_flood
14:23:02  firewall.forward.drop       forward 42 pkts (21 pps)
```

This is a **correlated** timeline, not a totally ordered one. Correlation
is by wallclock timestamp, not broker ordering.

## Backpressure

Container output is **never blocked**. Three levels protect the system:

1. **atomics high-watermark** in `forward_output/3` — drops before
   message allocation if >2000 chunks in flight
2. **bounded queue** in publisher state — drops oldest if >1000 chunks
3. **drop accounting** — every drop emits `system.log.overflow` event

The pipeline is **at-most-once**. Logs are complete as long as the
broker is reachable and output rate is below the watermark. Drops
are visible via AMQP events.

## Multiple Incarnations

When a container restarts, new output appends to the same stream.
Incarnations are distinguishable via headers:

- `instance` — unique UUID prefix per spawn (primary identity)
- `boot` — restart count within BEAM session
- `seq` — monotone sequence, resets to 0 per incarnation

## Requirements

- RabbitMQ with `rabbitmq_stream` plugin enabled:
  ```bash
  rabbitmq-plugins enable rabbitmq_stream
  ```
- AMQP enabled in erlkoenig sys.config (`{amqp, #{enabled => true, ...}}`)
