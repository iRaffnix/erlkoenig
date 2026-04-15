# Chapter 4 — Containers & Pods

A container in erlkoenig is a single Linux process running in its own
namespace bundle, orchestrated by an Erlang `gen_statem`. Containers never
live alone: they are grouped into *pods*, each pod its own supervisor
subtree. A pod is the smallest unit of deployment — it has a restart
strategy, a lifecycle, a name. This chapter documents every option of both.

## Pods as the logical bracket

The pod is the place where *restart coupling* is declared. When one
container inside a pod fails, the pod's `strategy:` decides what happens
to its siblings:

- **`:one_for_one`** — restart only the failed container. The common case.
- **`:one_for_all`** — restart every container in the pod. Use when
  containers share state (e.g. init + worker that writes a socket).
- **`:rest_for_one`** — restart the failed container and every container
  defined after it. Ordering matters.

A pod block takes a name (binary) and exactly one required option,
`strategy:`:

```elixir
pod "web", strategy: :one_for_one do
  container "api",  binary: "...", zone: "dmz", replicas: 3, restart: :permanent
  container "auth", binary: "...", zone: "dmz", replicas: 1, restart: :permanent
end
```

## Container options

Four options are required on every container: `binary:`, `zone:`,
`replicas:`, `restart:`. Everything else has a documented default.

| Option        | Type                    | Default    | Meaning                                           |
|---------------|-------------------------|------------|---------------------------------------------------|
| `binary:`     | string                  | required   | Absolute path to the static binary                |
| `zone:`       | string                  | required   | IPVLAN zone name (→ Chapter 5)                    |
| `replicas:`   | positive integer        | required   | How many copies of this container to run          |
| `restart:`    | atom                    | required   | See *restart policies* below                      |
| `args:`       | list of strings         | `[]`       | Arguments passed to `execve()`                    |
| `image:`      | string                  | `nil`      | Optional EROFS image path (composefs)             |
| `ports:`      | list                    | `[]`       | Port metadata (audit only, no forwarding)         |
| `limits:`     | map                     | `%{}`      | cgroup v2 limits — memory, cpu, pids              |
| `seccomp:`    | `:default` \| `:none` \| `:auto` | `:default` | Seccomp profile selection (→ Chapter 13)      |
| `uid:` / `gid:` | integer               | 65534      | UID/GID the binary runs as inside the container   |
| `caps:`       | list of atoms           | `[]`       | Linux capabilities to keep (see below)            |
| `volume` block | —                     | none       | Persistent bind-mounts (→ Chapter 8)              |
| `publish` block | —                    | none       | Cgroup metric emission (→ Chapter 9)              |
| `stream` block | —                     | none       | stdout/stderr streaming (→ Chapter 11)            |

## Restart policies

Three aliases, identical semantics, pick whichever fits your voice:

| DSL alias (OTP)  | Legacy name    | Meaning                                    |
|------------------|----------------|--------------------------------------------|
| `:permanent`     | `:always`      | Always restart, no matter the exit reason  |
| `:transient`     | `:on_failure`  | Restart only on abnormal exit (non-zero)   |
| `:temporary`     | `:no_restart`  | Never restart                              |

`erlkoenig.erl` accepts both spellings; the OTP names (`:permanent`,
`:transient`, `:temporary`) are the recommended DSL form because they
match the vocabulary developers already use for child specs.

A container that restarts doesn't retry immediately. The backoff is
exponential: 1 s, 2 s, 4 s, 8 s, 16 s, capped at 30 s. The counter resets
after the container stays up long enough — a shortcut against crash loops.

## Replicas and zones

Each replica of a container is a separate state machine with its own name
(`<pod>-<N>-<container>`), its own IP from the zone's pool, its own
persistent volumes. Replicas are not load-balanced by erlkoenig — that's
the service layer's job; erlkoenig just runs N independent copies.

`zone:` is a string that must match an `ipvlan` zone declared inside
`host do ... end`. The container gets placed in that zone's IP pool.
Sharing a zone across pods is fine; the IP allocator is per-zone and
collision-free.

## Limits and capabilities

The `limits:` map is passed straight through to the cgroup controller:

```elixir
container "api", binary: "...", zone: "dmz", replicas: 1, restart: :permanent,
  limits: %{memory: 256 * 1024 * 1024,    # 256 MB hard ceiling
            pids: 256,                      # fork bomb limit
            cpu: 50}                        # 50% of one core (weight-based)
```

Memory and pids are *kill factors*: the kernel OOMs or blocks `fork()` at
those limits. CPU is a weight, not a cap — a container with `cpu: 50`
under contention gets half a core, under idle conditions it can burn more.

Capabilities default to *none*. Adding `caps: [:net_raw]` keeps the
single bit you need for raw sockets; anything you don't list is dropped
before `execve()`. This is the primary Linux security lever; the chapter
on runtime internals (→ Chapter 12) covers the drop sequence.

## The state machine

A container transitions through the following states:

```
creating ──→ namespace_ready ──→ starting ──→ running
                                                │
                         ┌──────────────────────┼──────────────────────┐
                         ▼                      ▼                      ▼
                     stopping              disconnected              failed
                         │                      │                      │
                         ▼                      │                      │
                      stopped ◄─────────────────┘                      │
                         │                                             │
                    ┌────┴────┐                                        │
                    ▼         ▼                                        │
                restarting  (exit)                                 (inspect)
                    │
                    └──→ creating
```

A few states deserve attention:

- **`recovering`** is the first state after a BEAM restart if the
  container's OS process is still alive. The state machine reattaches
  to the running container instead of respawning.
- **`disconnected`** means the Unix socket to the C runtime was lost but
  the kernel process is still alive. The state machine tries to
  reconnect.
- **`failed`** is terminal-until-inspected: the container stays around
  long enough to grab its exit reason and logs, then transitions to
  `stopped` or `restarting` according to policy.

## Where this chapter points

- `volume` blocks inside a container → → Chapter 8
- `zone:` as a reference to a network zone → → Chapter 5
- `publish` / `stream` blocks (observability) → → Chapter 9 and → Chapter 11
- Why `seccomp: :default` is usually enough → → Chapter 13
