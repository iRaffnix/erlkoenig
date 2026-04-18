# Chapter 9 — Observability

Every interesting event in erlkoenig is an AMQP message. Container
lifecycle, cgroup metrics, firewall drops, threat detections, log
streams, configuration loads — all published onto a single topic
exchange `erlkoenig.events` with hierarchical routing keys. Consumers
subscribe to the slices they care about.

## The event bus

Inside the BEAM, events flow through `erlkoenig_events` — a gen_event
manager. Any module calls `erlkoenig_events:notify(Event)` and the
event is handed to every registered handler. One handler is always present: `erlkoenig_event_log` (writes to the
Erlang logger). When the AMQP publisher starts and connects to
RabbitMQ, it dynamically registers `erlkoenig_amqp_forwarder` which
encodes events and publishes them to the exchange.

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

| Metric         | Payload fields (map)                                 |
|----------------|------------------------------------------------------|
| `:memory`      | `current, peak, max, pct, swap`                      |
| `:cpu`         | `usec, delta_usec, throttled_usec, nr_throttled`     |
| `:pids`        | `current, max`                                       |
| `:pressure`    | `cpu_some_avg10, cpu_some_avg60, memory_some_avg10, io_some_avg10` |
| `:oom_events`  | `kills, events, high, max`                           |

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

## Hands-on: subscribe, trigger, observe

Bring up a container with `publish` enabled, subscribe to the event
bus, and watch events fire in real time.

**1. Stack with cgroup publishing.** Save as `~/obs_demo.exs`:

```elixir
defmodule ObsDemo do
  use Erlkoenig.Stack

  host do
    ipvlan "obs", parent: {:dummy, "ek_obs"}, subnet: {10, 77, 0, 0, 24}
  end

  pod "o", strategy: :one_for_one do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9000"],
      zone: "obs",
      replicas: 1,
      restart: :permanent do

      publish interval: 2_000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end
  end
end
```

```bash
ek dsl compile ~/obs_demo.exs -o /tmp/obs.term
ek up /tmp/obs.term
```

**2. Subscribe to the bus.** In a second terminal:

```bash
tools/event_consumer.py amqp://erlkoenig@localhost '#'
```

The wildcard `#` matches every routing key. You should see:

    container.o-0-echo.started    { pid: 156329, ip: "10.77.0.2" }
    stats.o-0-echo.memory         { current: 2411520, peak: 2457600, ... }
    stats.o-0-echo.cpu            { usec: 15234, delta_usec: 15234, ... }
    stats.o-0-echo.pids           { current: 1, max: 100 }
    stats.o-0-echo.memory         { current: 2412544, ... }      # 2s later
    stats.o-0-echo.cpu            { ... }
    stats.o-0-echo.pids           { ... }
    ...

Three stats events every two seconds, one per declared metric.

**3. Slice by category.** Separate consumers for different patterns:

```bash
# Only lifecycle transitions
tools/event_consumer.py amqp://... 'container.*.*'

# Only stats
tools/event_consumer.py amqp://... 'stats.#'

# Everything the firewall produces
tools/event_consumer.py amqp://... 'firewall.#'

# Threat detection
tools/event_consumer.py amqp://... 'guard.threat.*'

# Anything that went wrong
tools/event_consumer.py amqp://... 'error.*.*'
```

Routing-key patterns are the topic exchange's standard syntax: `*`
matches one word, `#` matches zero or more.

**4. Trigger a drop event.** Kill the container to see a non-clean
exit:

```bash
os_pid=$(ek --format json ct inspect o-0-echo | jq -r .os_pid)
kill -9 $os_pid
```

The bus emits:

    container.o-0-echo.failed    { reason: {signal, 9}, exit_code: -1 }
    container.o-0-echo.restarting { backoff_ms: 1000 }
    container.o-0-echo.started    { pid: <new>, ... }

Use `ek ct inspect` to confirm the `restart_count` bumped.

**5. Dashboard view.** The richer TUI consumer:

```bash
tools/dashboard.py amqp://erlkoenig@localhost
```

Five panels update in place: overview (counts + rates), threats
(active bans), containers (running/failed/restarting), network
(drop counters), raw events (last 50 messages). Ctrl-C to exit.

**6. Structured errors in practice.** Force a configuration error to
see the error channel:

```bash
# Intentionally bad stack
cat > /tmp/bad.exs << 'EOF'
defmodule Bad do
  use Erlkoenig.Stack
  pod "p", strategy: :bogus do
    container "x", binary: "/no/such/file", zone: "none",
      replicas: 1, restart: :permanent
  end
end
EOF
ek dsl compile /tmp/bad.exs -o /tmp/bad.term
ek up /tmp/bad.term
```

The subscriber sees:

    error.config.invalid_strategy   { pod: "p", got: "bogus",
                                       valid: ["one_for_one",
                                               "one_for_all",
                                               "rest_for_one"] }

**7. Tear down.**

```bash
ek down /tmp/obs.term
```

The bus emits `container.o-0-echo.stopped` and the subscriber's
steady stream of stats events ceases.
