# Architecture

How a 68 KB C binary and an Erlang/OTP supervision tree
turn `clone()` into a production container runtime.

## Supervision Tree

```
erlkoenig_sup (rest_for_one)
│
├── pg (erlkoenig_pg)                Process groups — container discovery
├── erlkoenig_zone                   Zone registry (ETS-backed)
├── erlkoenig_zone_sup               Per-zone network infrastructure
│   └── zone_<name>_sup (rest_for_one)
│       ├── erlkoenig_bridge         Linux bridge via netlink
│       ├── erlkoenig_ip_pool        /24 subnet allocator
│       └── erlkoenig_dns            UDP server on bridge:53
├── erlkoenig_cgroup                 cgroups v2 manager
├── erlkoenig_events                 gen_event lifecycle bus
├── erlkoenig_health                 TCP liveness probes
├── erlkoenig_audit                  Append-only security event log
├── erlkoenig_pki                    X.509 trust store + chain validation
├── erlkoenig_ctl                    Unix socket management interface
└── erlkoenig_ct_sup (simple_one_for_one)
    └── erlkoenig_ct                 One gen_statem per container
```

**Why `rest_for_one` at the top?** Dependencies flow downward. If the zone
registry crashes, zone supervisors must restart — but the container supervisor
above doesn't need to. `rest_for_one` restarts everything *after* the crashed
child, nothing before it.

**Why `rest_for_one` per zone?** If a bridge goes down, the IP pool and DNS
that depend on it must restart. But a DNS crash doesn't affect the bridge.

**Why `simple_one_for_one` for containers?** Containers are dynamic,
short-lived, and manage their own restart logic. The supervisor is a factory,
not a guardian. Container processes are `temporary` — the supervisor never
restarts them. Instead, each `erlkoenig_ct` gen_statem handles its own
restart policy with exponential backoff.

## Container Lifecycle

Each container is a single `gen_statem` process (`erlkoenig_ct`) that
moves through 7 states:

```
creating ──► namespace_ready ──► starting ──► running
    ▲                                            │
    │                                        [exit]
    │                                            ▼
    └──────── restarting ◄──────────────── stopped
                                               │
                                          [max retries]
                                               ▼
                                            (exit)
```

### State: `creating`

The gen_statem opens an Erlang port to the `erlkoenig_rt` binary and sends
`CMD_SPAWN` over a `{packet, 4}` protocol. The C runtime calls `clone()`
with 5 namespace flags (PID, NET, MNT, UTS, IPC), sets up a tmpfs rootfs,
mounts `/proc` with masked paths, applies the seccomp filter, drops
capabilities to the requested bitmask, and replies with `REPLY_CONTAINER_PID`
containing the child's OS PID and netns path.

The child is now alive in its namespaces but **blocked** — it hasn't called
`exec()` yet. It waits for `CMD_GO`.

Before sending `CMD_GO`, the control plane verifies the binary signature
(if `signature mode` is `on`). The SHA-256 hash is checked against the
`.sig` file, the Ed25519 signature is validated, and the X.509 certificate
chain is verified against the configured trust roots. If any check fails,
the container transitions to `failed` and the event is recorded in the
audit log.

### State: `namespace_ready`

This is where the control plane sets up everything the container needs
before it can run. Five steps, in order:

1. **Cgroup** — create `/sys/fs/cgroup/erlkoenig/<id>/`, attach the child
   PID, write memory/CPU/PID limits
2. **eBPF device filter** — send `CMD_DEVICE_FILTER` to the C runtime,
   which attaches a `BPF_PROG_TYPE_CGROUP_DEVICE` program to the cgroup
3. **Network** — allocate IP from the zone's pool, create a veth pair via
   netlink, move one end into the container's netns, attach the other to
   the bridge. Send `CMD_NET_SETUP` so the C runtime configures the
   interface inside the namespace (`setns()` + netlink)
4. **Firewall** — create a per-container nf_tables chain with forward rules,
   NAT/DNAT for port mappings
5. **Files** — write any configured files into the rootfs via `CMD_WRITE_FILE`

Then send `CMD_GO`. The C runtime calls `exec()`.

### State: `running`

The container is executing. The gen_statem:
- Joins the `pg` process group (makes the container discoverable)
- Registers in the zone's DNS server
- Forwards `REPLY_STDOUT`/`REPLY_STDERR` to the output callback
- Responds to `stop` calls by sending `SIGTERM`, waiting 5s, then `SIGKILL`

### State: `stopped`

Cleanup happens in reverse order of setup:
- Leave `pg` group
- Remove nf_tables chain
- Unregister from DNS
- Delete veth pair
- Destroy cgroup
- Release IP back to pool

Then check the restart policy.

### Restart Policies

```erlang
no_restart                %% default — don't restart
on_failure                %% restart on non-zero exit or signal
always                    %% restart on any exit
{on_failure, N}           %% restart on failure, max N attempts
{always, N}               %% restart on any exit, max N attempts
```

Backoff: 1s → 2s → 4s → 8s → 16s → 30s (capped). The container keeps its
identity, configuration, and explicit IP across restarts.

## Port Protocol

The Erlang ↔ C boundary is a single file descriptor with `{packet, 4}`
framing (4-byte big-endian length prefix). All messages are binary-encoded
with a 1-byte command tag followed by packed fields.

### Commands (Erlang → C)

| Tag    | Command              | Purpose                              |
|--------|----------------------|--------------------------------------|
| `0x10` | `CMD_SPAWN`          | Create namespaces, prepare child     |
| `0x11` | `CMD_GO`             | `exec()` the container binary        |
| `0x12` | `CMD_KILL`           | Send signal to container             |
| `0x13` | `CMD_CGROUP_SET`     | Write to cgroup file                 |
| `0x15` | `CMD_NET_SETUP`      | Configure IP inside netns            |
| `0x16` | `CMD_WRITE_FILE`     | Write file into rootfs               |
| `0x17` | `CMD_STDIN`          | Forward stdin data                   |
| `0x19` | `CMD_DEVICE_FILTER`  | Attach eBPF device filter to cgroup  |

### Replies (C → Erlang)

| Tag    | Reply                  | Payload                            |
|--------|------------------------|------------------------------------|
| `0x01` | `REPLY_OK`             | Command acknowledged               |
| `0x02` | `REPLY_ERROR`          | Error code + message               |
| `0x03` | `REPLY_CONTAINER_PID`  | OS PID + netns path                |
| `0x05` | `REPLY_EXITED`         | Exit code + signal                 |
| `0x07` | `REPLY_STDOUT`         | Output chunk                       |
| `0x08` | `REPLY_STDERR`         | Output chunk                       |

### CMD_SPAWN Wire Format

```
<<0x10,
  PathLen:16/big, Path/binary,           %% absolute binary path
  NumArgs:8, (Len:16/big, Arg/binary)*,  %% command-line arguments
  NumEnv:8,  (KLen:8, K, VLen:16, V)*,   %% environment variables
  Uid:32/big, Gid:32/big,               %% container user/group
  SeccompProfile:8,                       %% 0=none 1=default 2=strict 3=network
  RootfsSizeMB:32/big,                   %% tmpfs size (0 = default 64M)
  CapsKeep:64/big,                       %% capability bitmask
  DnsIp:32/big,                          %% DNS server (network order)
  Flags:32/big,                          %% bit 0 = PTY mode
  NumVolumes:8,                          %% 0..16 bind-mount volumes
  (SrcLen:16/big, Src/binary,            %% host directory (absolute)
   DstLen:16/big, Dst/binary,            %% container directory (absolute)
   Opts:32/big)*>>                       %% EK_VOLUME_F_* flags
```

The protocol is intentionally simple. No versioning beyond the initial
handshake byte. No streaming. Each command gets exactly one reply.
The C runtime is stateless between commands — all state lives in
the gen_statem on the Erlang side.

## Persistent Volumes

Containers have ephemeral rootfs (tmpfs) by default. For data that must
survive container restarts — databases, logs, uploads — Erlkoenig provides
**directory bind-mount volumes**.

### Design

- **Scope v1:** Directory bind-mounts only. No file mounts, no OverlayFS.
- **Persist names, not host paths:** The DSL declares `persist: "name"`, the
  core resolves the host path: `/var/lib/erlkoenig/volumes/<container>/<persist>/`
- **Semantic options:** The wire protocol carries `EK_VOLUME_F_*` flags, not
  raw `mount(2)` flags. The C runtime translates to the correct syscall sequence.
- **Read-only via two-step mount:** Initial `mount(MS_BIND)` followed by
  `mount(MS_BIND | MS_REMOUNT | MS_RDONLY)`. Direct `MS_RDONLY` on initial
  bind-mount is unreliable.

### Lifecycle

1. **Resolution:** On container create, `erlkoenig_volume:resolve/2` validates
   persist names (`[a-z0-9][a-z0-9_-]*`) and resolves host paths.
2. **Directory creation:** `erlkoenig_volume:ensure_volume_dir/1` creates the
   host directory if it doesn't exist. Existing directories are left untouched.
3. **Mount:** In `prepare_rootfs_in_child()`, after device mounts but before
   `pivot_root()`. The child creates the target directory under rootfs and
   bind-mounts the host directory. At this point the tmpfs rootfs is writable,
   host paths are visible, and mount propagation is private.
4. **Persist:** Volumes survive container stop/restart. The host directory
   is never automatically deleted.
5. **Audit:** `volume_mounted` and `volume_released` events are logged.

### DSL

```elixir
container :archive do
  binary "/opt/bin/archive"
  volume "/data/db", persist: "archive-db"
  volume "/var/log", persist: "archive-logs"
  volume "/etc/config", persist: "shared-config", read_only: true
end
```

### Security

- Container cannot call `mount(2)` — all capabilities dropped, seccomp blocks it
- Destination paths are validated component-wise (no `.`, `..`, empty segments)
- Host paths are never from untrusted input — derived from validated persist names
- The bind-mount happens before `pivot_root()`, so symlink escapes in the
  container filesystem are not possible (it's our tmpfs)

## Zone Architecture

Zones provide network isolation between groups of containers. Each zone
is an independent network segment with its own bridge, IP pool, and DNS.

```
Zone: dmz                          Zone: backend
┌─────────────────────┐            ┌─────────────────────┐
│ Bridge: ek_br_dmz   │            │ Bridge: ek_br_back  │
│ Subnet: 10.0.1.0/24 │            │ Subnet: 10.0.2.0/24 │
│ Gateway: 10.0.1.1   │            │ Gateway: 10.0.2.1   │
│                     │            │                     │
│ web    10.0.1.2     │            │ api    10.0.2.2     │
│ proxy  10.0.1.3     │            │ db     10.0.2.3     │
└─────────────────────┘            └─────────────────────┘
```

Containers in different zones cannot communicate unless explicitly allowed
by firewall rules. The zone's `policy` controls outbound behavior:
`allow_outbound` (default), `isolate` (no cross-zone), or `strict`
(no outbound at all).

Zones can be created and destroyed at runtime. When a zone supervisor
starts, it creates the bridge, starts the IP pool, and binds the DNS
server. When it stops, all resources are cleaned up via the `rest_for_one`
cascade.

### IP Allocation

Each zone has a `/24` pool (253 usable addresses, `.1` is the gateway).
The allocator hands out IPs sequentially and maintains a free list for
recycled addresses:

```erlang
allocate() ->
    case Free of
        [Octet | Rest] -> {ok, {A, B, C, Octet}};     %% reuse
        []             -> {ok, {A, B, C, Next}}         %% sequential
    end.
```

Containers with explicit IPs bypass the allocator entirely.

### DNS

Each zone runs a UDP DNS server bound to the bridge IP (e.g., `10.0.1.1:53`).
Container names are registered when a container enters the `running` state
and removed on `stopped`. Unknown queries are forwarded to an upstream
resolver (default: `8.8.8.8`).

Containers resolve each other by name within a zone automatically.
No `/etc/hosts`, no external DNS infrastructure.

## Crash Semantics

**Container process crashes (gen_statem dies unexpectedly):**
The Erlang port closes automatically, which sends `SIGHUP` to the C runtime.
The C runtime forwards `SIGKILL` to the container child and exits. Cgroup
and veth are cleaned up by the kernel when the namespace collapses.

**Bridge crashes:**
`rest_for_one` restarts the bridge, then the IP pool and DNS. Running
containers keep their veth pairs (already attached to the old bridge
device in the kernel), but new containers in that zone will use the
new bridge instance.

**Zone registry crashes:**
`rest_for_one` at the top level restarts the registry, then all zone
supervisors. Bridges are re-created, pools re-initialized, DNS re-bound.
Running containers are unaffected — their network stack is in-kernel.

**C runtime crashes:**
The port closes, the gen_statem receives `{Port, {exit_status, N}}`, and
transitions to `stopped`. If the restart policy allows it, a new C runtime
process is spawned and the container starts fresh.

## Firewall Integration

The firewall operates at two levels:

**Per-container ([`erlkoenig_firewall_nft`](../apps/erlkoenig_core/src/erlkoenig_firewall_nft.erl)):**
Creates an nf_tables table `erlkoenig_ct` with `forward`, `prerouting`,
`postrouting`, and `output` chains. Each container gets a jump rule in the
forward chain and DNAT rules for port mappings. Rules are added atomically
when a container enters `namespace_ready` and removed when it enters
`stopped`.

**Host firewall ([`erlkoenig_nft`](https://github.com/iRaffnix/erlkoenig_nft)):** A separate
OTP application with its own supervision tree. Manages the host's input
chain, blocklists, rate limiting, conntrack monitoring, and threat detection.

Both talk to the kernel via the same pure-Erlang netlink protocol stack,
but they manage separate nf_tables tables and operate independently.

## Design Decisions

**Erlang port, not a NIF.** The C runtime runs in a separate OS process.
If it segfaults, the BEAM continues. A NIF crash would take down the entire
VM. The port protocol adds ~50 microseconds of latency per command —
irrelevant for container lifecycle operations.

**One gen_statem per container, not one gen_server.** The container lifecycle
has clear states with different valid operations in each. A gen_server would
need manual state tracking with case statements. The gen_statem makes invalid
state transitions impossible and per-state timeouts trivial.

**pg for discovery, not ETS.** Process groups automatically remove dead
processes. No cleanup code needed. And when Erlang distribution is enabled,
`pg` works across nodes — container discovery becomes cluster-wide for free.

**Netlink for networking, not `ip` commands.** Bridge creation, veth pairs,
IP assignment — all done via `AF_NETLINK` sockets from Erlang. No
`os:cmd("ip link add ...")`. This eliminates shell injection risks, removes
the `iproute2` dependency, and is faster (no fork+exec per operation).

**Unix socket, not Erlang distribution.** Management happens over
`/run/erlkoenig/ctl.sock`, not via `epmd` or the Erlang distribution
protocol. No TCP ports for administration. Permissions enforced by the
kernel (filesystem permissions on the socket file). Every command is
logged to the audit log.

**Signature verification at exec(), not at deployment.** Most container
runtimes verify image signatures when pulling from a registry or via an
admission controller. Erlkoenig verifies at the moment of execution —
including after automatic crash restarts. An attacker who replaces a
binary between restarts is caught.

**Temporary children with self-managed restarts.** OTP's built-in restart
strategies are designed for long-lived services. Container restart policies
need exponential backoff, max-retry limits, and failure classification
(exit code 0 is not a failure). Implementing this inside the gen_statem
gives full control without fighting the supervisor.

## Source Map

### Erlang Control Plane

| Module | Role |
|--------|------|
| `erlkoenig_core` | Public API: `spawn/2`, `stop/1`, `list/0`, `inspect/1` |
| `erlkoenig_ct` | Container gen_statem (lifecycle, port protocol, restart) |
| `erlkoenig_proto` | Binary codec for the port protocol |
| `erlkoenig_sup` | Root supervisor (`rest_for_one`) |
| `erlkoenig_zone` | Zone registry (ETS + gen_server) |
| `erlkoenig_zone_sup` | Creates per-zone supervisor subtrees |
| `erlkoenig_bridge` | Linux bridge lifecycle (netlink) |
| `erlkoenig_ip_pool` | Sequential `/24` allocator with free-list recycling |
| `erlkoenig_dns` | Per-zone UDP DNS server with upstream forwarding |
| `erlkoenig_net` | Veth creation, bridge attachment, netns operations |
| `erlkoenig_cgroup` | cgroups v2 hierarchy (systemd-aware path detection) |
| `erlkoenig_health` | TCP probes with configurable retry and restart trigger |
| `erlkoenig_firewall_nft` | Per-container nf_tables chains |
| `erlkoenig_events` | gen_event bus for lifecycle hooks |
| `erlkoenig_audit` | Append-only JSON Lines security event log |
| `erlkoenig_pki` | X.509 trust store, certificate chain validation |
| `erlkoenig_sig` | Ed25519 binary signing and verification |
| `erlkoenig_ctl` | Unix socket management server (`/run/erlkoenig/ctl.sock`) |
| `erlkoenig_ctl_proto` | Binary request/response protocol for ctl socket |

### C Runtime

| File | Role |
|------|------|
| `erlkoenig_rt.c` | Port program main loop, command dispatch |
| `erlkoenig_ns.c` | `clone()` + namespace setup, seccomp, capability drop |
| `erlkoenig_netcfg.c` | In-container network config via `setns()` + netlink |
| `erlkoenig_cgroup_dev.c` | eBPF cgroup device filter attachment |
