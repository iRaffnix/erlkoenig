# Networking

erlkoenig creates isolated Layer 2 network segments using Linux bridges
and veth pairs. All network setup happens via pure Netlink calls — no
`ip` CLI, no shell commands.

## Topology

```
                    Internet
                       │
                    ┌──┴──┐
                    │ eth0 │  (physical interface, zone: :wan)
                    └──┬──┘
                       │
          ┌────────────┼────────────┐
          │            │            │
     ┌────┴────┐  ┌────┴────┐  ┌───┴─────┐
     │   dmz   │  │   app   │  │  data   │  (bridges)
     │10.0.0/24│  │10.0.1/24│  │10.0.2/24│
     └────┬────┘  └────┬────┘  └────┬────┘
          │            │            │
      ┌───┴───┐    ┌───┴───┐   ┌───┴───┐
      │vh.web │    │vh.app │   │vh.data│   (host veth)
      │  0nginx│    │  0api │   │  0pg  │
      └───┬───┘    └───┬───┘   └───┬───┘
          │            │            │
      ┌───┴───┐    ┌───┴───┐   ┌───┴───┐
      │vp.web │    │vp.app │   │vp.data│   (container veth)
      │  0nginx│    │  0api │   │  0pg  │
      │  .0.2  │    │  .1.2 │   │  .2.2 │   (IP from pool)
      └───────┘    └───────┘   └───────┘
      namespace    namespace   namespace
```

## Bridges

Each `bridge` creates a Linux bridge — an isolated Layer 2 broadcast domain.
Containers attached to the same bridge can communicate directly.
Traffic between different bridges must pass through the nftables forward chain.

```elixir
host do
  interface "eth0", zone: :wan

  bridge "dmz",  subnet: {10, 0, 0, 0, 24}, uplink: "eth0"  # internet-facing
  bridge "app",  subnet: {10, 0, 1, 0, 24}                   # internal only
  bridge "data", subnet: {10, 0, 2, 0, 24}                   # isolated
end
```

- **Subnet**: `{a, b, c, d, mask}` — IPv4 CIDR notation
- **Gateway**: automatically `.1` (e.g. `10.0.0.1`)
- **IP Pool**: `.2` through `.254` — allocated to containers
- **Uplink**: connects bridge to physical interface (needed for internet access, requires NAT)

## Veth Pairs

Each container gets a veth pair: one end in the host namespace (attached to
the bridge), one end in the container namespace.

Naming convention:
- Host side: `vh.<pod><index><container>` (e.g. `vh.web0nginx`)
- Container side: `vp.<pod><index><container>` (e.g. `vp.web0nginx`)

In nft rules, `{:veth_of, "pod", "container"}` resolves to the host veth name:

```elixir
# Matches traffic FROM the nginx container
nft_rule :jump, iifname: {:veth_of, "web", "nginx"}, to: "from-web-nginx"
```

## IP Allocation

IPs are allocated sequentially from the bridge's pool:

```elixir
attach "web", to: "dmz", replicas: 3
# web-0-nginx → 10.0.0.2
# web-1-nginx → 10.0.0.3
# web-2-nginx → 10.0.0.4
```

In nft rules, `{:replica_ips, "pod", "container"}` expands to all replica IPs:

```elixir
# Allows traffic to ALL nginx replicas on port 8443
nft_rule :accept,
  iifname: "eth0",
  ip_daddr: {:replica_ips, "web", "nginx"},
  tcp_dport: 8443
```

With `replicas: 3`, this generates three individual nft rules — one per IP.

## NAT / Masquerade

Containers in isolated bridges (no uplink) cannot reach the internet.
For outbound access, add a masquerade rule in the postrouting chain:

```elixir
base_chain "postrouting", hook: :postrouting, type: :nat,
  priority: :srcnat, policy: :accept do

  # Container traffic leaving the bridge gets source-NAT'd to host IP
  nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "dmz"
end
```

## Zone Reconciliation

When switching between configs (e.g. deploying a different stack file),
erlkoenig automatically:

1. Stops containers not in the new config
2. Destroys bridges not in the new config (including Netlink cleanup)
3. Recreates bridges whose subnet changed
4. Starts new containers

This enables hot reconfiguration without manual cleanup.
