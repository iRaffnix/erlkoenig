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
containers on the same host bypass the host's `forward` chain. Rules
that try to filter container-to-container traffic from the host side
have no effect. The right place for such rules is the container's own
nft table (→ Chapter 6).

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
`.1`, and the IP pool allocates `.2` through `.254`. Prefixes other
than `/24` are allowed but uncommon.

## IP pool and DNS

`erlkoenig_ip_pool` hands out IPs sequentially within each zone. Every
replica of every container gets its own address; when a container
stops, its IP returns to the pool.

DNS inside the container is handled by `erlkoenig_dns`. At spawn time
erlkoenig writes `/etc/resolv.conf` into the container's rootfs
pointing at the zone's gateway. For `{:dummy, ...}` zones the gateway
runs an internal resolver that knows every container in the zone, so
`curl http://auth/` works without external DNS configuration. For
`{:device, ...}` zones the host's resolver is forwarded.

Names follow the replica scheme: container `auth` in pod `web` is
registered as `web-0-auth`, `web-1-auth`, and so on. A container may
declare `dns_name:` to override that with something shorter.

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

## Outside the scope of this chapter

- Port forwarding from host to container. With one IP per container,
  bind the container directly to the port it wants.
- IPv6. Not wired into the DSL.
- Ingress from an external load balancer. erlkoenig sits below that
  layer — point the balancer at the container's IP.

For firewall rules that live inside the container's netns, see
→ Chapter 6.
