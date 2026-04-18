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
| `env:`        | map of string → string  | `%{}`      | Environment variables for the binary              |
| `files:`      | map of path → content   | `%{}`      | Files written into the rootfs before `execve()`   |
| `image:`      | string                  | `nil`      | Optional EROFS image path (composefs)             |
| `ports:`      | list                    | `[]`       | Port metadata (audit only, no forwarding)         |
| `limits:`     | map                     | `%{}`      | cgroup v2 limits — memory, cpu, pids              |
| `seccomp:`    | `:none` \| `:default` \| `:strict` \| `:network` | `:none`    | Seccomp profile (→ Chapter 13)           |
| `uid:` / `gid:` | integer               | 0          | UID/GID the binary runs as inside the container   |
| `caps:`       | list of atoms           | `[]`       | Linux capabilities to keep (see below)            |
| `health_check:` | map                   | none       | Reachability probe (→ Chapter 9)                  |
| `signature:`  | `:required` \| string   | none       | Require a valid Ed25519 signature (→ Chapter 10)  |
| `volume` block | —                     | none       | Persistent bind-mounts (→ Chapter 8)              |
| `publish` block | —                    | none       | Cgroup metric emission (→ Chapter 9)              |
| `stream` block | —                     | none       | stdout/stderr streaming (→ Chapter 11)            |
| `nft` block   | —                       | none       | Per-container netfilter rules (→ Chapter 6)       |

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
exponential and saturates quickly: 1 s, 2 s, 4 s, 8 s, 16 s, 30 s, then
30 s for every further attempt. The counter itself lives in `persistent_term`
keyed by container name; it survives pod-supervisor respawns and
drift-driven reconcile-restarts, and only resets when the name leaves
the declared stack entirely.

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
creating --> namespace_ready --> starting --> running
                                                |
                         +-----------+----------+-----------+
                         v           v                      v
                     stopping   disconnected              failed
                         |           |                      |
                         v           |                      |
                      stopped <------+                      |
                         |                                  |
                    +----+----+                             |
                    v         v                             |
                restarting  (exit)                      (inspect)
                    |
                    +--> creating

          recovering --> running     (BEAM restart: reattach to live process)
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

## Hands-on: seeing pod strategies in action

The three strategies look very similar on paper. The difference only
shows up when a container actually dies. This section puts three
minimal pods next to each other, kills the middle container in each,
and observes how the siblings react.

The stack file `examples/pod_strategies.exs` defines three pods:

```
pod "ofo", strategy: :one_for_one   → containers a, b, c
pod "ofa", strategy: :one_for_all   → containers a, b, c
pod "rfo", strategy: :rest_for_one  → containers a, b, c
```

Each container is a tiny echo server on a distinct IP in zone
`strategies` (10.99.200.0/24). Nine containers, one zone, one file.

```bash
cp /opt/erlkoenig/examples/pod_strategies.exs ~/strategies.exs
ek up ~/strategies.exs
ek ps
```

Snapshot the `os_pid` of every container:

```bash
for name in ofo-0-a ofo-0-b ofo-0-c \
            ofa-0-a ofa-0-b ofa-0-c \
            rfo-0-a rfo-0-b rfo-0-c; do
  printf '%-12s  ' "$name"
  ek --format json ct inspect $name \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["os_pid"])'
done
```

Now kill the middle container in each pod, bypassing erlkoenig:

```bash
for name in ofo-0-b ofa-0-b rfo-0-b; do
  kill -KILL $(ek --format json ct inspect $name \
                 | python3 -c 'import json,sys; print(json.load(sys.stdin)["os_pid"])')
done
sleep 4
```

Read the table again. What you should see:

| Pod  | -0-a         | -0-b          | -0-c          |
|------|--------------|---------------|---------------|
| ofo  | **unchanged**| new os_pid    | **unchanged** |
| ofa  | new os_pid   | new os_pid    | new os_pid    |
| rfo  | **unchanged**| new os_pid    | new os_pid    |

The `restart_count` in `ek ct inspect` echoes the coupling: in `ofo`
only `b` went to 1; in `ofa` all three; in `rfo` `b` and `c`. The
counter bumps for *every* gen_statem reincarnation, regardless of
whether that specific container was the one that crashed.

**Caveat for the coupled strategies.** `:one_for_all` and
`:rest_for_one` tear down siblings concurrently. The pod supervisor
respawns them the instant the old gen_statems exit, while the kernel
still holds the previous ipvlan slaves and their addresses. You may
see `net_setup_failed, -98, Address in use` transiently before the
new slaves settle. `:one_for_one` does not trigger this race; use it
for the first walkthrough and treat the other two as advanced.

## Hands-on: watching the backoff

Kill the same container three times in quick succession and watch the
backoff widen:

```bash
for i in 1 2 3; do
  T_BEFORE=$(date +%s)
  kill -KILL $(ek --format json ct inspect ofo-0-a \
                 | python3 -c 'import json,sys; print(json.load(sys.stdin)["os_pid"])')
  until ek ct inspect ofo-0-a 2>/dev/null | grep -q '^state .*running'; do
    sleep 0.5
  done
  T_AFTER=$(date +%s)
  printf 'kill #%d: %ds to recover, restart_count=%s\n' \
         "$i" $((T_AFTER - T_BEFORE)) \
         "$(ek --format json ct inspect ofo-0-a \
              | python3 -c 'import json,sys; print(json.load(sys.stdin)["restart_count"])')"
done
```

Expected timings: roughly 1 s, 2 s, 4 s. Pushing further — 8 s, 16 s,
30 s — is fine, but remember that a fifth consecutive crash within the
quarantine window (default 60 s) trips the crashloop quarantine: the
binary's hash is blacklisted and subsequent spawns return
`{error, {quarantined, …}}` until `ek quarantine remove` clears it.
The backoff itself saturates at 30 s and stays there regardless of
how many more attempts follow.

To wipe the counter, remove the container from the stack and
re-introduce it: `ek down` clears every name that leaves the declared
set, a subsequent `ek up` starts the affected names at 0 again.

```bash
ek down ~/strategies.exs
```

## Where this chapter points

- `volume` blocks inside a container → → Chapter 8
- `zone:` as a reference to a network zone → → Chapter 5
- `publish` / `stream` blocks (observability) → → Chapter 9 and → Chapter 11
- Why `seccomp: :default` is usually enough → → Chapter 13
