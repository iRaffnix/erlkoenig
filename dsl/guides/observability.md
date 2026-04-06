# Observability

All runtime events flow through a single AMQP topic exchange
(`erlkoenig.events`) on RabbitMQ. Routing keys follow the schema
`<category>.<entity>.<event>` — consumers can filter by container,
event type, or wildcard.

## Routing Key Schema (v2)

| Category | Routing Key | Description |
|----------|-------------|-------------|
| Container | `container.<name>.started` | Container reached running state |
| | `container.<name>.stopped` | Container exited |
| | `container.<name>.failed` | Fatal error |
| | `container.<name>.restarting` | Restart backoff started |
| | `container.<name>.oom` | OOM killed |
| | `container.<name>.health` | Health check failed |
| Stats | `stats.<name>.memory` | Memory usage |
| | `stats.<name>.cpu` | CPU time |
| | `stats.<name>.pids` | Process count |
| | `stats.<name>.pressure` | PSI stall information |
| | `stats.<name>.oom` | OOM kill counters |
| Firewall | `firewall.<chain>.drop` | Counter rate > 0 |
| | `firewall.<chain>.packet` | NFLOG packet details |
| Conntrack | `conntrack.flow.new` | New connection |
| | `conntrack.flow.destroy` | Connection ended |
| | `conntrack.alert.mode` | Mode switch |
| Guard | `guard.threat.ban` | IP banned |
| | `guard.threat.unban` | Ban expired |
| Control | `control.nft.ban` | Manual ban |
| | `control.set.add` | Set element added |
| Policy | `policy.<name>.violation` | Policy violation |

## Filtering Examples

```python
# All events for one container
queue.bind(exchange, "container.web-0-nginx.*")

# Memory of all containers
queue.bind(exchange, "stats.*.memory")

# All firewall events
queue.bind(exchange, "firewall.#")

# Everything
queue.bind(exchange, "#")
```

## Envelope Format (v2)

```json
{
  "v": 2,
  "ts": "2026-04-05T18:00:01.234Z",
  "node": "erlkoenig@worker-1",
  "key": "stats.web-0-nginx.memory",
  "payload": {
    "name": "web-0-nginx",
    "current": 110592,
    "peak": 524288,
    "max": 268435456,
    "pct": 0.04,
    "swap": 0
  }
}
```

## Stats Payloads

### Memory (`:memory`)
```json
{"name": "web-0-nginx", "current": 110592, "peak": 524288, "max": 268435456, "pct": 0.04, "swap": 0}
```
- `pct` = `current / max * 100` (0.0 if max is unlimited)

### CPU (`:cpu`)
```json
{"name": "web-0-nginx", "usec": 690, "delta_usec": 12, "throttled_usec": 0, "nr_throttled": 0}
```
- `delta_usec` = difference since last poll (useful for utilization rate)

### PIDs (`:pids`)
```json
{"name": "web-0-nginx", "current": 2, "max": 100}
```

### Pressure (`:pressure`)
```json
{"name": "web-0-nginx", "cpu_some_avg10": 0.0, "memory_some_avg10": 0.0, "io_some_avg10": 0.0}
```
PSI (Pressure Stall Information) — measures how much processes are
waiting for resources. Unlike CPU/memory utilization, PSI shows
**impact**: a container at 95% CPU with `avg10 = 0.0` is fine.
`avg10 > 0` means processes are stalling.

### OOM Events (`:oom_events`)
```json
{"name": "web-0-nginx", "kills": 0, "events": 0, "high": 0, "max": 0}
```

## Python Consumer

```bash
# Listen to everything
python3 tools/event_consumer.py 178.104.16.107 "#"

# Only stats for one container
python3 tools/event_consumer.py 178.104.16.107 "stats.web-0-nginx.*"

# Firewall drops
python3 tools/event_consumer.py 178.104.16.107 "firewall.#"
```

Sample output:
```
19:01:07     web-0-echo  mem=104.0K peak=368.0K cpu=0us pids=2/max
19:01:09     web-0-echo  mem=104.0K peak=368.0K cpu=0us pids=2/max
19:01:15     web-0-echo  psi:ok oom:ok
19:01:21      conntrack  NEW  tcp 54.38.145.60:58666 -> 178.104.17.63:22
```

## DSL Configuration

Stats are opt-in per container via `publish` blocks:

```elixir
container "api", binary: "/opt/api" do
  publish interval: 2000 do    # fast: every 2s
    metric :memory
    metric :cpu
    metric :pids
  end

  publish interval: 30_000 do  # slow: every 30s
    metric :pressure
    metric :oom_events
  end
end
```

No `publish` block → no stats events → zero overhead.
