# DSL Documentation Plan

ExDoc `@doc` annotations for all macros in `Erlkoenig.Stack`,
grouped by domain. Each group is one work unit.

Deployed automatically via GitHub Pages: https://iraffnix.github.io/erlkoenig/

## Status

- [x] Group 1: Container (pod, container, publish, metric) — 4 macros
- [ ] Group 2: Firewall / nft — 7 macros
- [ ] Group 3: Network / Topology — 4 macros
- [ ] Group 4: Security / Guard — 5 macros
- [ ] Group 5: Module-level (@moduledoc) — 4 modules

## Group 2: Firewall / nft (ADR-0015)

The nft-transparent DSL. Each rule maps 1:1 to a real nftables rule.
This is the most complex group — `nft_rule` alone has ~20 match fields
and 13 actions.

| Macro | Options | Description |
|-------|---------|-------------|
| `nft_table` | `family`, `name` | Table container (`:inet`, `:ip`, `:ip6`) |
| `base_chain` | `hook:`, `type:`, `priority:`, `policy:` | Chain attached to netfilter hook |
| `nft_chain` | `name` | Regular chain (jump target) |
| `nft_rule` | `action`, 20+ match opts | Single nft rule |
| `nft_counter` | `name` | Named counter object |
| `nft_set` | `name`, `type`, `flags:` | Named set |
| `nft_vmap` | `name`, `type`, `entries` | Verdict map |

### nft_rule match fields to document

| Field | nft equivalent | Example |
|-------|---------------|---------|
| `ct_state:` | `ct state` | `[:established, :related]` |
| `iifname:` | `iifname` | `"eth0"`, `{:veth_of, "pod", "ct"}` |
| `oifname:` | `oifname` | `"br0"` |
| `oifname_ne:` | `oifname !=` | `"dmz"` |
| `tcp_dport:` | `tcp dport` | `8080`, `{8000, 9000}` (range) |
| `udp_dport:` | `udp dport` | `53` |
| `ip_saddr:` | `ip saddr` | `{10,0,0,0,24}`, `{:replica_ips, "pod", "ct"}` |
| `ip_daddr:` | `ip daddr` | `{10,0,0,2}`, `{:replica_ips, "pod", "ct"}` |
| `ip6_saddr:` | `ip6 saddr` | IPv6 tuple |
| `iif:` | `iif` (index) | `"lo"` |
| `log_prefix:` | `log prefix` | `"FWD: "` |
| `counter:` | `counter` | `"forward_drop"` (named) |
| `to:` | jump target | `"from-web-nginx"` (with `:jump`) |
| `mark:` | `ct mark set/match` | `1` (with `:ct_mark_set`/`:ct_mark_match`) |
| `snat_to:` | `snat to` | `{192,168,1,1}` |
| `dnat_to:` | `dnat to` | `{10,0,0,2}`, `{10,0,0,2, 8080}` (IP+port) |
| `limit:` | `ct count` | `100` (with `:connlimit_drop`) |
| `set:` | `@set_name` | `"blocklist"` (set lookup) |
| `vmap:` | `vmap @name` | `"dispatch"` (with `:vmap_dispatch`) |

### nft_rule actions to document

| Action | Description | Required opts |
|--------|-------------|---------------|
| `:accept` | Accept packet | — |
| `:drop` | Drop packet | — |
| `:return` | Return to calling chain | — |
| `:jump` | Jump to named chain | `to:` |
| `:masquerade` | SNAT to outgoing interface IP | — |
| `:reject` | Reject with ICMP response | — |
| `:notrack` | Skip connection tracking | — |
| `:ct_mark_set` | Set conntrack mark | `mark:` |
| `:ct_mark_match` | Match on conntrack mark | `mark:` |
| `:snat` | Source NAT | `snat_to:` |
| `:dnat` | Destination NAT | `dnat_to:` |
| `:fib_rpf` | Reverse path filter (BCP38) | — |
| `:connlimit_drop` | Connection limit per IP | `limit:` |
| `:vmap_dispatch` | Verdict map dispatch | `vmap:` |

## Group 3: Network / Topology

| Macro | Context | Options | Description |
|-------|---------|---------|-------------|
| `host` | top-level | — | Machine configuration block |
| `interface` | inside `host` | `zone:` | Physical network interface |
| `bridge` | inside `host` | `subnet:`, `uplink:` | Virtual bridge (L2 segment) |
| `attach` | top-level | `to:`, `replicas:` | Deploy pod to bridge |

### Key concepts to document
- Subnet format: `{10, 0, 0, 0, 24}` — 4-tuple + netmask
- IP pool: automatic allocation from subnet (x.x.x.2 .. x.x.x.254)
- Gateway: auto-assigned .1 address
- Uplink: bridge to physical interface for internet access
- Replicas: how pod instances are numbered (`web-0-nginx`, `web-1-nginx`)
- `{:veth_of, "pod", "container"}` — resolved at deploy time
- `{:replica_ips, "pod", "container"}` — expanded to IP list at deploy time

## Group 4: Security / Guard

| Macro | Context | Options | Description |
|-------|---------|---------|-------------|
| `guard` | top-level | — | Threat detection block |
| `detect` | inside `guard` | `threshold:`, `window:` | Detection rule |
| `ban_duration` | inside `guard` | seconds | Auto-ban duration |
| `whitelist` | inside `guard` | IP tuple | Never-ban IP |
| `watch` | top-level | name | Conntrack/nflog watcher |

### Detection types to document
- `:conn_flood` — too many new connections from one IP
- `:port_scan` — too many distinct destination ports from one IP

## Group 5: Module-level docs

| Module | Description |
|--------|-------------|
| `Erlkoenig.Stack` | Main @moduledoc: overview, quick start, full example |
| `Erlkoenig.Pod.Builder` | Builder internals, term format |
| `Erlkoenig.Nft.TableBuilder` | Table accumulator, validation |
| `Erlkoenig.Nft.ChainBuilder` | Chain types, rule validation |

## Conventions

- Every `@doc` starts with a one-line summary
- Options as markdown tables: `| Option | Type | Default | Description |`
- At least one `## Examples` section with working code
- Reference nft equivalent where applicable (e.g. "corresponds to `nft add rule ... tcp dport 8080 accept`")
- Validation errors documented (what raises CompileError)
