# Networking

erlkoenig connects containers with **IPVLAN L3S** slaves placed directly into
the container's network namespace. All link creation runs via pure Netlink
calls — no `ip` CLI, no shell commands, and no host-side veth pairs (see
ADR-0020 for the history of the bridge removal).

## Topology

```
                    Internet
                       │
                    ┌──┴──┐
                    │ eth0 │  (physical parent, shared by all slaves)
                    └──┬──┘
                       │
                 ┌─────┼─────┐
                 │     │     │
              ┌──┴──┬──┴──┬──┴──┐
              │slave│slave│slave│   (IPVLAN L3S slaves,
              │.0.2 │.0.3 │.0.4 │    each in its own netns)
              └──┬──┴──┬──┴──┬──┘
                 │     │     │
              netns  netns  netns
```

Each slave has the same MAC as the parent. The kernel does per-slave L3
forwarding between them — there is no host-visible host-side interface.
Container-to-container traffic stays inside the IPVLAN fast path and does
**not** pass through the host `FORWARD` chain (by design).

## Zones

A **zone** is an IPVLAN parent + subnet. It is declared via `ipvlan`:

```elixir
host do
  ipvlan "dmz",  parent: {:device, "eth0"},    subnet: {10, 0, 0, 0, 24}
  ipvlan "app",  parent: {:dummy,  "ek_app"},  subnet: {10, 0, 1, 0, 24}
  ipvlan "data", parent: {:dummy,  "ek_data"}, subnet: {10, 0, 2, 0, 24}
end
```

Parent types:
- `{:device, "eth0"}` — an existing host interface. Traffic exits the box
  via this link. Required for external connectivity.
- `{:dummy,  "ek_<name>"}` — erlkoenig auto-creates a kernel `dummy0`
  parent. The dummy owns the subnet but never sees real traffic; slaves
  forward to each other via the kernel's IPVLAN code.

Subnet notation: `{a, b, c, d, mask}` (IPv4 CIDR).
- `.1` is reserved as gateway (only present for dummy parents).
- `.2`–`.254` are handed out to containers by the IP pool.

Bare strings as `parent:` are rejected at compile time.

## IP Allocation

IPs are allocated sequentially from the zone's pool. Each container inside
a pod declares its own `zone:` and `replicas:`:

```elixir
pod "web", strategy: :one_for_one do
  container "nginx",
    binary: "/opt/nginx",
    zone: "dmz", replicas: 3, restart: :permanent
end
# web-0-nginx → 10.0.0.2
# web-1-nginx → 10.0.0.3
# web-2-nginx → 10.0.0.4
```

Because slaves share the parent's MAC and are not visible in the host netns,
**rules must key on IPs, not interface names**. The DSL keys
`ip_saddr`/`ip_daddr` take either a single IP or a CIDR tuple:

```elixir
# Allow DMZ → APP TCP 4000
nft_rule :accept,
  ip_saddr: {10, 0, 0, 0, 24},   # everything in dmz
  ip_daddr: {10, 0, 1, 0, 24},   # to everything in app
  tcp_dport: 4000
```

For per-replica addressing, expand the pool yourself — interface helpers like
`{:veth_of, ...}` or `{:replica_ips, ...}` are gone (they were bridge-era).

## NAT / Masquerade

Containers on a dummy parent cannot reach the internet directly. For outbound
access, masquerade through the uplink interface:

```elixir
base_chain "postrouting", hook: :postrouting, type: :nat,
  priority: :srcnat, policy: :accept do

  nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "eth0"
end
```

## Per-Container Firewall

IPVLAN L3S fires the OUTPUT/INPUT hooks inside the container netns. The DSL
exposes these via a `nft do ... end` block on a container:

```elixir
container "nginx", binary: "/opt/nginx", args: ["8443"] do
  nft do
    output do
      nft_rule :accept, ct_state: [:established, :related]
      nft_rule :accept, ip_daddr: {10, 0, 1, 0, 24}, tcp_dport: 4000
      nft_rule :drop
    end
  end
end
```

At container boot the runtime sends `CMD_NFT_SETUP` with the compiled nft
batch; the C binary calls `setns()` into the container netns and applies the
rules atomically. See SPEC-EK-023.

## Zone Reconciliation

When switching between configs (e.g. deploying a different stack file),
erlkoenig automatically:

1. Stops containers not in the new config
2. Recreates zones whose parent or subnet changed (dummy parents only)
3. Starts new containers

Slaves inside a container netns disappear when the container exits — there
is no separate host-side cleanup.
