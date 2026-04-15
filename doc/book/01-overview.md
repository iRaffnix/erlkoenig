# Chapter 1 — Overview

**Erlkoenig — Speed and Control.**

A container runtime for Linux, deliberately lean. A 168 KB static C binary
(`erlkoenig_rt`) spawns the Linux namespaces; the BEAM (Erlang/OTP 28) does
everything else — networking through Netlink, firewalling through nftables
(pure Erlang, no `nft` CLI on the hot path), cgroups v2 with PSI metrics,
Ed25519 signatures, AMQP events. An Elixir DSL compiles to Erlang terms, no
YAML. About 50 milliseconds per container spawn.

## The five layers

Every container travels the same path from source to kernel:

```
┌──────────────────────────────────────────────────────┐
│  Elixir DSL (.exs)                                   │
│  defmodule MyStack do                                │
│    use Erlkoenig.Stack                               │
│    host / ipvlan / pod / container / nft_table / ... │
│  end                                                 │
└──────────────┬───────────────────────────────────────┘
               │ mix compile → Code.compile_file/1
               ▼
┌──────────────────────────────────────────────────────┐
│  Erlang term (.term)                                 │
│  #{pods => [...], zones => [...], nft_tables => ...} │
└──────────────┬───────────────────────────────────────┘
               │ erlkoenig_config:load/1
               ▼
┌──────────────────────────────────────────────────────┐
│  BEAM — orchestration                                │
│                                                      │
│  erlkoenig_ct        per container (gen_statem)      │
│  erlkoenig_pod_sup   per pod                         │
│  erlkoenig_zone      IPVLAN parent + IP pool         │
│  erlkoenig_nft_*     nftables in Erlang              │
│  erlkoenig_volume_*  volumes, metadata, stats        │
└──────────────┬───────────────────────────────────────┘
               │ Unix socket + TLV protocol
               ▼
┌──────────────────────────────────────────────────────┐
│  C runtime (erlkoenig_rt)                            │
│  namespaces, rootfs, bind-mounts, caps, seccomp      │
└──────────────┬───────────────────────────────────────┘
               │ clone3 / mount / setns / execve
               ▼
┌──────────────────────────────────────────────────────┐
│  Linux kernel                                        │
└──────────────────────────────────────────────────────┘
```

The DSL is compiled once into an Erlang term, the term is validated on load
and expanded into supervisor specs, the BEAM starts one `gen_statem` per
container that talks to the C binary over a Unix socket, and the C binary
drives the kernel primitives.

Each layer has a single clear responsibility. A change at one level has
predictable consequences only for the layer below — the DSL knows nothing
about TLV bytes, the C binary knows nothing about pods.

## Orchestration in the BEAM

The supervisor tree starts in `erlkoenig_sup.erl` with strategy
`rest_for_one`: pg → zone registry → zone supervisor → cgroup → events →
health → audit → PKI → nft supervisor → volume store → volume stats → pod
supervisor. If a child dies, all later children restart; earlier ones stay
stable. Containers themselves live inside *pods*, their own supervisor
subtrees, never as bare processes under the root supervisor.

This has two consequences. First, a crash in a pod never takes down the
BEAM. Second, the pod's restart strategy (`one_for_one`, `one_for_all`,
`rest_for_one`) determines how tightly containers inside a pod are coupled
— a standard OTP lever, surfaced through the DSL.

## Security and networking

The firewall is pure Erlang. `erlkoenig_nft_firewall` and its container
counterparts (`erlkoenig_nft_container`) speak AF_NETLINK directly — no
`nft` fork, no shell escaping. Rules are data: written as DSL, compiled to
NLMSG batches, applied atomically. This makes hot-reload deterministic and
compilation fast enough to sit inside a deploy hook.

Networking uses IPVLAN in L3-symmetric mode. Every container gets its own
IP on the same host parent device. Netfilter hooks fire inside each
container's own namespace, and FORWARD traffic between containers does
not exist. Firewall semantics follow directly: rules hang off IP
addresses, not interface visibility.

Threat detection runs as per-IP `gen_statem` instances
(`erlkoenig_threat_actor`). Every suspicious IP gets its own process with
its own state; bans are synchronised across nodes through a `pg`-based
mesh. The kernel holds the ban list in nft sets with timeouts — the actual
enforcement is below userspace.

## Boot and recovery

The app starts via `erlkoenig_app.erl`. First a DETS file holding
previously-persisted container state is read. Then `recovery/0` runs: for
each persistent container, the app checks whether the OS process is still
alive, and if so reattaches the BEAM to the running container instead of
respawning it. This is the key property for production: a BEAM restart
does not take containers with it.

Only after recovery does the supervisor tree come up, the firewall gets
installed, and containers marked for autostart in the config go live.

## Where to go next

To get a running system, follow → Chapter 2 (Installation) and
→ Chapter 3 (Your First Container). To learn the DSL concretely, jump
straight to → Chapter 4 (Containers & Pods). To understand the kernel side,
read → Chapter 12 (Runtime Architecture).
