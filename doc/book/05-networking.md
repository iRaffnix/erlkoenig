# Chapter 5 — Networking

erlkoenig uses a single networking model: IPVLAN in L3-symmetric mode.
Every container gets its own IPv4 address on a shared host parent device,
the kernel routes between them, and netfilter hooks fire inside each
container's own namespace. This chapter explains how that model maps onto
the DSL.

## The L3S model

The parent device keeps its MAC address. Each container holds an IPVLAN
*slave* on top of that parent, and the kernel routes packets to the
right slave based on destination IP. Containers cannot see each other
at L2 — no broadcast, no ARP between them. The Linux netfilter hooks
live inside the container's own network namespace, which is what makes
per-container firewall rules meaningful.

One consequence matters for firewall design: packets between two
containers on the same IPVLAN parent bypass the host's `forward`
chain entirely. The ipvlan driver fast-paths them via
`ipvlan_l3_rcv()` without traversing the host's netfilter. Rules in
the host's forward chain that try to filter container-to-container
traffic within the same zone have no effect — the kernel never
evaluates them. The only firewall layer that sees this traffic is
the container's own nft table (→ Chapter 6).

## Zones and host devices

A *zone* names a parent device plus an IPv4 subnet. Zones are declared
once, inside the top-level `host do ... end` block, and every container
references a zone by name:

```elixir
host do
  ipvlan "dmz",      parent: {:device, "eth0"},   subnet: {10, 0, 0, 0, 24}
  ipvlan "internal", parent: {:dummy,  "ek_int"}, subnet: {10, 0, 1, 0, 24}
end
```

Two parent-device flavours exist:

- **`{:device, "eth0"}`** — an existing physical or virtual host
  interface. Packets leave the host over that interface with the
  container's IP as source. Used where containers need routable IPs.
- **`{:dummy, "ek_int"}`** — a dummy interface that erlkoenig creates
  and manages itself. Nothing leaves the host; containers in the zone
  reach each other and the host, and nothing else. Used for internal
  service meshes.

The subnet tuple is `{A, B, C, D, prefix}`. The gateway is always
`.1`, and the IP pool allocates `.2` through the broadcast minus one.
Prefixes from /16 to /30 are accepted; the pool sizes itself
accordingly. Anything narrower than /30 leaves no room for the
gateway plus a single container and is rejected on load.

## Zones, pods, and namespaces

A *zone* is not a network namespace. Three separate concepts sit next
to each other in the DSL and it's worth keeping them apart:

- **Pod** — an OTP supervisor group. Drives restart strategy, nothing
  else. Containers in the same pod share a supervisor tree; they do
  not share a network. Two containers in different pods can share a
  zone, and two containers in the same pod can sit in different zones.
- **Zone** — a shared IP network. One IPVLAN parent, one subnet, one
  gateway, one IP pool. Every container with `zone: "tutorial"` hangs
  off the same parent device and can address every other container in
  the zone by IP. One zone per parent device, declared once in
  `host do ... end`.
- **Netns** — per-container network namespace. Each container runs in
  its own `/proc/<pid>/ns/net` with its own routing table, its own
  interfaces, and its own nft tables. A zone membership gives the
  container one IPVLAN slave inside that netns.

What the runtime actually builds when a zone is declared:
1. A dummy interface in the host netns (for `{:dummy, ...}` zones),
   created once, independent of any container.
2. An IP-pool process that hands out `.2` through `.254` on demand.
3. A host-side IPVLAN slave (`h.<dummy>`) in the host netns carrying
   the gateway IP `.1`. This is what makes host-to-container traffic
   routable.
4. On each container start: a further IPVLAN slave created directly
   in that container's netns (one-shot via netlink — never moved
   after the fact).

The consequence for firewall design is the one mentioned above:
container-to-container traffic in the same zone is fast-pathed by
the ipvlan driver between two slaves on the same parent. It never
crosses the host's `forward` chain. The only layer that sees this
traffic is the container's own nft tables — `output` in the sender's
namespace, `input` in the receiver's. Host-side forward rules simply
don't fire for same-zone peers.

A practical rule of thumb: *pod* controls what restarts; *zone*
controls who can address whom; *netns + nft* controls who actually
gets through.

## IP pool and DNS

`erlkoenig_ip_pool` hands out IPs sequentially within each zone. Every
replica of every container gets its own address; when a container
stops, its IP returns to the pool.

DNS inside the container is handled by `erlkoenig_dns`. At spawn time
the C runtime writes `/etc/resolv.conf` pointing at the zone's
gateway, and the BEAM-side `erlkoenig_dns` listens on UDP/53 at that
gateway IP. The same resolver runs for both `{:dummy, ...}` and
`{:device, ...}` zones: it answers `<name>.erlkoenig` queries from a
zone-local registry and forwards everything else to the upstream
resolver configured via the `dns_upstream` application env (default
`8.8.8.8`).

**The DNS server is a runtime service that lives on the host.**
Container → gateway DNS lookups arrive on the host's `input` hook,
not on `forward`, because the host-side IPVLAN slave terminates
them in the host netns. erlkoenig does not silently inject allow
rules for its own services — the host nft table you write is the
single source of truth. The standard pattern for exposing the DNS
resolver to its zone is one explicit rule:

```elixir
nft_rule :accept, ip_saddr: {10, 99, 0, 0, 24}, udp_dport: 53
```

Every example DSL in `examples/` carries this rule under a clearly
labelled "Runtime services" section. The pattern, the rationale,
and the full service catalogue are covered in → Chapter 6.

Names follow the replica scheme: container `auth` in pod `web` is
registered as `web-0-auth`, `web-1-auth`, and so on.

## The host-side slave

Dummy zones have one additional interface worth knowing about. The
dummy itself carries no IP; the gateway `.1` lives on a separate
IPVLAN slave in the host namespace, conventionally named
`h.<dummy-name>`. Without that slave no host-namespace interface
answers for the gateway IP, and host-to-container traffic silently
times out.

Operators normally don't interact with this interface. It appears in
`ip link show` and is managed by `erlkoenig_zone_link_ipvlan`.
Deleting it by hand takes the zone offline.

## Typical topologies

**Single flat zone.** One `{:device, "eth0"}` zone with every
container in it. Simplest setup; the firewall enforces whatever
isolation is needed.

**DMZ plus internal.** A `{:device, "eth0"}` zone named `dmz` for
frontend containers with routable IPs, and a `{:dummy, "ek_int"}` zone
named `internal` for backends that never touch the outside. The
firewall on the dmz zone blocks access to internal from outside.

**Shared parent, multiple zones.** Two zones can sit on the same
physical parent with different subnets. The kernel routes correctly;
IP allocation stays per-zone. Useful for multi-tenant deployments
where every tenant gets its own subnet.

## Hands-on: seeing the model from inside

Three small experiments make the L3S model concrete. They assume a
running tutorial stack (→ Chapter 3) — `app-0-web` on `10.99.0.2`,
`app-0-api` on `10.99.0.4`, gateway `10.99.0.1`.

**1. DNS round-trip.** From inside one container, look up a sibling
by name:

```bash
NG=$(ek --format json ct inspect app-0-web | \
       python3 -c 'import json,sys; print(json.load(sys.stdin)["netns_path"])')
nsenter --net=$NG nslookup app-0-api.erlkoenig
# → Server:    10.99.0.1
# → Address:   10.99.0.1#53
# → Name:      app-0-api.erlkoenig
# → Address:   10.99.0.4
```

The resolver runs in the BEAM on the host, listens on the gateway
IP `10.99.0.1` inside the zone, and answers from a registry that
`erlkoenig_ct` writes to on every container start. Names that don't
match `*.erlkoenig` are forwarded to the upstream resolver
(`dns_upstream` env, default `8.8.8.8`).

**2. L2 isolation.** Two slaves on the same parent cannot see each
other at L2. ARP from one container's netns to a sibling returns
nothing:

```bash
nsenter --net=$NG arping -c 2 -I i.app0web 10.99.0.4
# → Sent 2 probes (1 broadcast(s))
# → Received 0 response(s)
```

But the same container reaches that IP just fine via L3:

```bash
nsenter --net=$NG ping -c 1 -W 1 10.99.0.4
# → 64 bytes from 10.99.0.4: icmp_seq=1 ttl=64 time=...
```

This is the L3S model's defining property: no broadcast, no ARP,
only kernel routing by destination IP. Switching attacks across
peers (ARP poisoning, gratuitous ARP, MAC spoofing) are simply
not on the wire.

**3. Host-slave criticality.** Delete the host-side slave and
host-to-container TCP times out — but container-to-container keeps
working, because that traffic never crosses the host slave:

```bash
ip link show h.ek_tut          # the slave that carries 10.99.0.1
nc -w2 10.99.0.2 8080          # works: replies from web
ip link del h.ek_tut
nc -w2 10.99.0.2 8080          # times out: nothing on the host
                               # answers for 10.99.0.1 anymore
nsenter --net=$NG nc -w2 10.99.0.4 4000   # still works: never went via host
```

Recreating it (the runtime does this automatically on next zone use,
or you can reload the stack) restores host-side reachability. Two
practical consequences:

- **The dummy alone is not enough.** The IPVLAN parent device carries
  no IP. Routing only works because of the host slave that *does*
  carry the gateway IP.
- **Inter-container traffic survives host network glitches.** Even
  if the host slave is misconfigured or removed, the containers can
  still reach each other through the parent — useful to know during
  emergency recovery.

## Outside the scope of this chapter

- Port forwarding from host to container. With one IP per container,
  bind the container directly to the port it wants.
- IPv6. Not wired into the DSL.
- Ingress from an external load balancer. erlkoenig sits below that
  layer — point the balancer at the container's IP.

For firewall rules that live inside the container's netns, see
→ Chapter 6.
