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

## Where to go next

- Chapter 4 (Containers & Pods) covers what happens after admission
  accepts and quarantine clears a spawn.
- Chapter 6 (Firewall) covers what rules the nft worker holds and
  how they compile; Chapter 14 (Netlink Transport) covers the
  transport it uses.
- Chapter 9 (Observability) lists all routing keys mentioned here
  plus the container and stats families.
