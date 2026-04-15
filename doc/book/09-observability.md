# Chapter 9 — Observability

Every interesting event in erlkoenig is an AMQP message. Container
lifecycle, cgroup metrics, firewall drops, threat detections, log
streams, configuration loads — all published onto a single topic
exchange `erlkoenig.events` with hierarchical routing keys. Consumers
subscribe to the slices they care about.

## The event bus

Inside the BEAM, events flow through `erlkoenig_events` — a gen_event
manager. Any module calls `erlkoenig_events:notify(Event)` and the
event is handed to every registered handler. Two handlers ship by
default: `erlkoenig_event_log` (writes to the Erlang logger) and
`erlkoenig_amqp_forwarder` (encodes the event and publishes to
RabbitMQ).

The forwarder runs `erlkoenig_amqp_codec:encode/1` on every event.
That function pattern-matches the event tuple and produces a tuple
of routing key plus JSON payload. An unmatched event is dropped
silently — unknown tuples don't reach the wire. Consumers see
exactly the events the codec knows how to name.

## Routing key schema

The exchange is a topic exchange; routing keys are dot-separated
hierarchies. The top-level categories:

| Prefix                          | Source                                       |
|---------------------------------|----------------------------------------------|
| `container.<name>.*`            | lifecycle (started, stopped, failed, oom, health) |
| `stats.<name>.*`                | cgroup metrics (memory, cpu, pids, pressure, oom_events) |
| `stats.volume.<ct>.<persist>`   | per-volume disk usage                        |
| `firewall.<chain>.*`            | counters and NFLOG drops                     |
| `conntrack.flow.*`              | new and destroyed flows                      |
| `guard.threat.*`                | bans, unbans, honeypots, suspicions          |
| `control.<scope>.*`             | runtime control (nft reload, set add/del)    |
| `policy.<name>.violation`       | policy engine rejections                     |
| `metrics.<name>.*`              | BPF tracepoints (fork, exec, exit)           |
| `system.*`                      | config load/fail, firewall applied, log overflow |
| `security.<name>.*`             | signature verified or rejected               |
| `error.<type>.<reason>`         | structured errors                            |

Every key is derived from the event tuple — not configurable, not
hand-assigned. The event code is the source of truth; the codec
maps patterns to prefixes.

## The `publish` block

Cgroup metrics are opt-in per container. Without a `publish` block
no stats events fire for that container, which keeps noise down on
busy hosts. A container subscribes by declaring one or more
`publish` blocks:

```elixir
container "api", binary: "...", zone: "dmz",
  replicas: 3, restart: :permanent do

  publish interval: 2_000 do
    metric :memory
    metric :cpu
    metric :pids
  end

  publish interval: 10_000 do
    metric :pressure
    metric :oom_events
  end
end
```

`interval:` is in milliseconds, minimum 1000. Multiple `publish`
blocks are allowed — typical usage is a fast interval for memory/CPU
(where spikes matter) and a slower one for pressure and OOM (where
sustained values matter).

The five metric atoms map onto cgroup v2 interfaces:

| Metric         | Payload                                              |
|----------------|------------------------------------------------------|
| `:memory`      | `{current, peak, max, pct, swap}`                    |
| `:cpu`         | `{usec, delta_usec, throttled_usec, nr_throttled}`   |
| `:pids`        | `{current, max}`                                     |
| `:pressure`    | `{cpu_some_avg10, memory_some_avg10, io_some_avg10}` |
| `:oom_events`  | `{kills, events, high, max}`                         |

Each metric produces its own event — `stats.web-0-api.memory`,
`stats.web-0-api.cpu`, and so on.

## Volume stats

Separately from container metrics, `erlkoenig_volume_stats` polls
registered volumes and publishes disk usage per volume. The routing
key is `stats.volume.<container>.<persist>`. The payload carries
`bytes`, `inodes`, `lifecycle`, `uuid`, and a timestamp. The
defaults (60-second interval, enabled) are tunable through sys.config
keys `volume_stats_interval_ms` and `volume_stats_enabled`.

## Structured errors

Errors pass through the same bus. Any module that detects a failure
at a boundary (bad config, network timeout, missing file, signature
rejection) emits an `erlkoenig_error:emit/1` call; the event lands
as `error.<type>.<reason>` on the wire. The payload is a map with
`type`, `reason`, `context`, severity level, and a stack trace
fingerprint. Dashboards render errors separately from informational
events — coloured, copyable, surfaced above the main event stream.

## Consumers

Two shipped tools read the bus:

- **`tools/event_consumer.py`** — a command-line subscriber that
  prints any matching routing-key pattern. Useful for ad-hoc
  debugging: `event_consumer.py <broker> 'guard.threat.*'`
  watches threat detection; `'container.*.started'` prints spawns.

- **`tools/dashboard.py`** — a Textual-based TUI with five panels
  (overview, threats, containers, network, raw events). Aggregates
  stats per second, colours errors, groups routing keys. Designed to
  run in a persistent terminal alongside operations work.

Both rely on the same envelope format: every AMQP message carries
headers for node identity and an event version, plus the JSON
payload produced by the codec. Consumers that want to build their
own decoders should read `erlkoenig_amqp_codec.erl` — it's the
schema.
