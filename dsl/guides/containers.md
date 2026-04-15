# Containers & Pods

## Container Lifecycle

Each container is an Erlang `gen_statem` with the following states:

```
creating ──→ namespace_ready ──→ starting ──→ running
                                                │
                                    ┌───────────┼───────────┐
                                    ▼           ▼           ▼
                                 stopping    disconnected  failed
                                    │           │           │
                                    ▼           │           ▼
                                  stopped ◄─────┘       (inspect)
                                    │
                              ┌─────┴─────┐
                              ▼           ▼
                          restarting    (exit)
                              │
                              └──→ creating
```

- **creating**: C runtime started via Unix socket, handshake in progress
- **namespace_ready**: Container PID known, network setup window (IPVLAN slave, IP, cgroup, firewall)
- **starting**: GO command sent, waiting for ack
- **running**: Container executing, stats timers active
- **stopping**: SIGTERM sent, waiting for exit (5s timeout → SIGKILL)
- **stopped**: Cleanup done, check restart policy
- **restarting**: Exponential backoff (1s, 2s, 4s, 8s, 16s, 30s cap)
- **disconnected**: Socket lost but container may still be alive (reconnect attempt)
- **failed**: Error state, process stays alive for inspection

## Pods

A pod groups containers that belong together. The pod determines
how containers are supervised — which restart strategy to use when
one of them crashes.

```elixir
# Independent: each container restarts on its own
pod "workers", strategy: :one_for_one do
  container "a", binary: "/opt/a", restart: :always
  container "b", binary: "/opt/b", restart: :always
end

# Coupled: if one dies, all restart
pod "backend", strategy: :one_for_all do
  container "app",   binary: "/opt/app",   restart: :always
  container "cache", binary: "/opt/cache", restart: :always
end

# Pipeline: crash restarts it + everything after it
pod "pipeline", strategy: :rest_for_one do
  container "ingest",    binary: "/opt/ingest",    restart: :always
  container "transform", binary: "/opt/transform", restart: :always
  container "export",    binary: "/opt/export",    restart: :always
  # kill transform → transform + export restart, ingest stays
end
```

## Naming

Container names are generated from pod, replica index, and container name:

```
<pod>-<index>-<container>

web-0-nginx       first replica of nginx in pod web
web-1-nginx       second replica
app-0-api         first API instance
app-0-worker      first worker (same pod as api)
```

## Resource Limits

Limits are enforced via cgroups v2:

```elixir
container "api",
  binary: "/opt/api",
  limits: %{
    memory: 1_073_741_824,   # 1 GB — hard kill at this limit
    cpu: 50,                  # 50% of one core (cpu.max = 500000 1000000)
    pids: 200                 # max 200 processes (fork bomb protection)
  }
```

### cgroup Hierarchy

```
/sys/fs/cgroup/system.slice/erlkoenig.service/
├── beam/           ← BEAM VM (memory.min guarantee, cpu.weight priority)
└── containers/     ← ceiling for all containers
    ├── <id-1>/     ← per-container limits
    ├── <id-2>/
    └── ...
```

The BEAM is protected: `memory.min` guarantees a minimum reservation,
`cpu.weight` gives scheduling priority. Containers cannot starve the BEAM.

The C runtime (`erlkoenig_rt`) writes its own PID into the container
cgroup before any allocation — so even the runtime process itself
counts against container limits, not the BEAM.

## Restart Policies

| Policy | Triggers on | Max retries |
|--------|-------------|-------------|
| `:no_restart` | never | — |
| `:always` | any exit | unlimited |
| `:on_failure` | non-zero exit / signal | unlimited |
| `{:always, n}` | any exit | `n` |
| `{:on_failure, n}` | non-zero exit / signal | `n` |

Backoff: 1s → 2s → 4s → 8s → 16s → 30s (capped). Resets after
successful run.

## Health Checks

```elixir
container "api",
  binary: "/opt/api",
  health_check: [port: 4000, interval: 10_000, retries: 3]
```

erlkoenig periodically connects to the specified port. After `retries`
consecutive failures, a `container.<name>.health` AMQP event is published.

## Metrics Publishing

Containers can opt into periodic cgroup metrics via `publish` blocks:

```elixir
container "api", binary: "/opt/api" do
  # Fast: every 2 seconds
  publish interval: 2000 do
    metric :memory     # current, peak, max, pct, swap
    metric :cpu        # usec, delta_usec, throttled
    metric :pids       # current, max
  end

  # Slow: every 30 seconds
  publish interval: 30_000 do
    metric :pressure   # PSI: cpu/memory/io avg10
    metric :oom_events # kills, events, high, max
  end
end
```

Events flow via AMQP: `stats.app-0-api.memory`, `stats.app-0-api.cpu`, etc.

No `publish` block = no stats events (zero overhead).
