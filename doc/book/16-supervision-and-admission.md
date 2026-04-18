# Chapter 16 — Supervision & Admission

Three OTP-level features govern how containers are *allowed to run* and
*allowed to fail*. They sit below the DSL — there's nothing to configure
inside a `container` block for them — but their behaviour shapes what
happens during a burst deployment, a crashloop, or a firewall outage.

## Fail-closed firewall

The nft firewall worker is a *significant* child of its supervisor.
When a child marked significant terminates and its parent supervisor
has `auto_shutdown => any_significant`, the supervisor shuts down
cleanly. The flag is set at two levels in the tree:

- `erlkoenig_nft_firewall` is significant inside `erlkoenig_nft_sup`;
  `erlkoenig_nft_sup` has `auto_shutdown => any_significant`.
- `erlkoenig_nft_sup` itself is significant inside `erlkoenig_sup`;
  `erlkoenig_sup` has `auto_shutdown => any_significant`.

The chain is: if the firewall worker's restart intensity is exceeded,
`nft_sup` auto-shuts-down → `erlkoenig_sup` auto-shuts-down → the
BEAM exits with reason `shutdown`. systemd — if configured — restarts
the whole runtime.

The outcome: containers never run while the firewall state is
uncertain. A transient crash still recovers through the normal
supervisor restart; only a *repeated* crash triggers the fail-closed
path. The restart intensity (five crashes in sixty seconds by
default) is the dividing line.

## Crashloop quarantine

`erlkoenig_quarantine` is a gen_server that watches container
failures. Every time a container enters the `failed` state — or the
`restarting` state, if the state machine is about to back off — the
module records a crash keyed by the SHA-256 of the container's
binary. When the same hash sees `threshold` crashes inside
`window_ms`, the hash is *quarantined*.

A quarantined hash is refused on future spawn attempts. The
pre-spawn gate in `erlkoenig_ct`'s `creating` state calls
`erlkoenig_quarantine:check/1` before any namespace setup; a
quarantined hash returns `{error, {quarantined, Hash, Since}}` and
the container transitions straight to `failed` with a clear
error_reason. No socket is opened, no rootfs is built, no nft rule
is installed.

Tuning lives in sys.config:

```erlang
{quarantine_enabled,   true},
{quarantine_threshold, 5},
{quarantine_window_ms, 60000},
```

Disabling is per-node (set `quarantine_enabled` to `false`). Lifting
a single quarantine during operations is one call:

```erlang
erlkoenig_quarantine:unquarantine(<<"sha256-hex-hash">>).
```

The list is memory-resident. A restart of the erlkoenig service
clears it — useful as a coarse "I've fixed the underlying issue"
reset. Persistent quarantine across restarts is intentionally not
provided: restarts are operator actions that usually accompany a
fix.

AMQP: a hash entering quarantine emits
`security.<hash-prefix>.quarantined`; a lift emits
`security.<hash-prefix>.unquarantined`. The prefix is the first
twelve hex characters of the SHA-256, enough to disambiguate and
short enough to read.

## Admission gate

`erlkoenig_admission` is a bounded-concurrency gate in front of the
expensive part of the spawn path. Before any Unix-socket connect
or CMD_SPAWN, the state machine calls `acquire/2` with the
container's zone as scope; when the spawn reaches `running`, the
token is released. Failed and stopped transitions release the
token too, so a failing spawn doesn't permanently consume a slot.

The gate has two independent caps:

- **Host cap** (`admission_max_host`, default 10). Global across
  every zone. Prevents the BEAM from driving the kernel into
  contention with too many in-flight namespace setups at once.
- **Per-zone cap** (`admission_max_per_zone`, default 0, meaning
  *disabled*). Protects a single zone's IP pool or firewall
  reload path from a deployment that would otherwise create ten
  containers into the same zone at once.

Waiters queue up to `admission_queue_limit` (default 100). Past
that, new `acquire/2` calls return `{error, queue_full}`
immediately. An existing waiter times out after
`admission_acquire_timeout_ms` (default 30 seconds) and its
container transitions to `failed` with a clean
`admission_timeout` reason.

Tuning lives in sys.config:

```erlang
{admission_max_host,           10},
{admission_max_per_zone,        0},
{admission_queue_limit,       100},
{admission_acquire_timeout_ms, 30000},
```

A cap of zero means unlimited. Setting `admission_max_host` to `0`
disables the gate entirely — useful for development environments
where bursty spawns of one or two containers aren't worth gating.

AMQP: `admission.<scope>.accepted`, `admission.<scope>.waiting`,
`admission.<scope>.timeout`. `<scope>` is either `host` or a zone
name. Dashboards that want to surface "we're sitting in the
admission queue" subscribe to the `waiting` events specifically.

## How the three fit together

The three features are independent in code but compose at runtime.
A healthy deployment looks like:

1. Admission gate accepts up to *max_host* parallel spawns.
2. Each in-flight spawn runs the quarantine check before anything
   expensive. A quarantined binary fails fast with a clear reason.
3. The container reaches `running`, and from there regular
   lifecycle takes over. Restart policies, limits, seccomp, and
   firewall rules apply as usual.
4. If a binary turns into a crashloop, the quarantine threshold
   is eventually crossed and the hash gets blocked. Subsequent
   spawn attempts fail fast instead of hammering the kernel.
5. If the firewall gen_server itself crashes beyond its own
   supervisor's tolerance, the fail-closed chain takes the whole
   runtime down; systemd brings it back with a fresh state, and
   containers return only once the firewall is healthy again.

All three are *operator-visible but not operator-configured* in
normal use: they shape the runtime's behaviour without anyone
having to think about them. The DSL stays clean; the product's
security and stability properties land in the supervisor tree.

## Hands-on: trip all three safety nets

Each of the three mechanisms (fail-closed firewall, crashloop
quarantine, admission gate) can be tripped deliberately to observe
the behaviour.

**1. Crashloop quarantine.** Write a container that exits immediately:

```bash
cat > /tmp/crash.c << 'EOF'
int main(void) { return 1; }
EOF
musl-gcc -static -o /tmp/crash /tmp/crash.c

cat > ~/crash.exs << 'EOF'
defmodule CrashStack do
  use Erlkoenig.Stack
  host do
    ipvlan "c", parent: {:dummy, "ek_c"}, subnet: {10, 120, 0, 0, 24}
  end
  pod "cp", strategy: :one_for_one do
    container "crasher", binary: "/tmp/crash", args: [],
      zone: "c", replicas: 1, restart: :permanent
  end
end
EOF

ek dsl compile ~/crash.exs -o /tmp/crash.term
ek up /tmp/crash.term
```

Watch the container crash, restart, crash again — the exponential
backoff stretches out to 30 s. After 5 failures within 60 s, the
runtime logs:

    [erlkoenig_quarantine] binary quarantined
    hash=<SHA256>  reason={crashloop,5,60000}

Further spawns of that binary fail immediately with `{quarantined, Hash}`.
Lift it manually once the underlying issue is fixed:

```bash
ek quarantine list
ek quarantine remove <hash>
```

Clean up: `ek down /tmp/crash.term`.

**2. Admission gate saturation.** Declare a pod that asks for more
concurrent spawns than the host's admission limit allows:

```elixir
pod "bp", strategy: :one_for_one do
  container "w",
    binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
    args: ["9000"],
    zone: "b", replicas: 30, restart: :permanent
end
```

In another terminal, snapshot the admission gate during the spawn
burst: `watch -n0.5 ek admission snapshot`.

Expected: `in_flight` sits at `max_host` (default 10), `queue`
climbs, then drains as each spawn completes. All 30 containers
eventually come up — the gate paces, it doesn't drop.

If the queue had overflowed (`queue_limit`, default 100), the
overflow spawns would fail with `{admission, queue_full}` rather
than queuing forever.

**3. Fail-closed firewall.** Kill the nft firewall gen_server
repeatedly to trigger its significant-child fail-closed behaviour:

```erlang
%% In an erlkoenig remote_console:
exit(whereis(erlkoenig_nft_firewall), kill).       %% restarts
[exit(whereis(erlkoenig_nft_firewall), kill)
   || _ <- lists:seq(1, 10)].                      %% exceeds intensity
```

The daemon exits. systemd respawns it, the firewall comes back up
with fresh state. During the outage, existing containers keep
running (their kernel state is independent), but **no new spawn
succeeds** — the spawn gate treats a missing firewall as fail-closed.

In production this is almost impossible to hit — the firewall
gen_server is thin. But the supervisor-tree invariant stands: if
the firewall is broken, nothing new runs.

## Where to go next

- Chapter 4 (Containers & Pods) covers what happens after admission
  accepts and quarantine clears a spawn.
- Chapter 6 (Firewall) covers what rules the nft worker holds and
  how they compile; Chapter 14 (Netlink Transport) covers the
  transport it uses.
- Chapter 9 (Observability) lists all routing keys mentioned here
  plus the container and stats families.
