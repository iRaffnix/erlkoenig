# Firewall (nft-transparent DSL)

erlkoenig's firewall DSL maps 1:1 to real nftables rules. No abstraction
layer, no hidden semantics. Every `nft_rule` corresponds to exactly one
`nft add rule` command. See [ADR-0015](https://github.com/iRaffnix/erlkoenig/blob/main/docs/decisions/0015-nft-transparent-dsl.md).

## How It Works

```
DSL (Elixir)              nftables (Kernel)
─────────────             ──────────────────
nft_table :inet, "fw"  →  nft add table inet fw
base_chain "input"     →  nft add chain inet fw input { type filter hook input priority filter; policy drop; }
nft_rule :accept, ...  →  nft add rule inet fw input ct state established,related accept
nft_counter "drops"    →  nft add counter inet fw drops
```

The DSL compiles to an Erlang term. At deploy time, `erlkoenig_config`
translates rules to Netlink messages via `erlkoenig_nft` — no `nft` CLI involved.

## Packet Flow

```
                    Incoming Packet
                         │
                    ┌────┴────┐
                    │ INPUT?  │──── destined for host ──→ input chain
                    └────┬────┘
                         │ forwarded
                    ┌────┴────┐
                    │ FORWARD │──→ forward chain
                    └────┬────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
         iifname?   ct state?   ip daddr?
              │          │          │
         jump to     accept     accept if
         egress      if est.    port matches
         chain
              │
         ┌────┴────┐
         │ EGRESS  │  (regular chain)
         │ from-*  │  checks what container may SEND
         └────┬────┘
              │
         accept / drop
```

## Two-Level Filtering

### 1. Egress Chains (what can a container send?)

Regular chains entered via `jump` from the forward chain.
Each container gets its own egress chain:

```elixir
# Forward chain: route to egress chains based on source veth
nft_rule :jump, iifname: {:veth_of, "web", "nginx"}, to: "from-web-nginx"
nft_rule :jump, iifname: {:veth_of, "app", "api"},   to: "from-app-api"

# Nginx: may only talk to API on :4000
nft_chain "from-web-nginx" do
  nft_rule :accept, ct_state: [:established, :related]
  nft_rule :accept, tcp_dport: 4000
  nft_rule :drop, counter: "nginx_drop"       # everything else → counted drop
end

# API: may only talk to DB on :5432
nft_chain "from-app-api" do
  nft_rule :accept, ct_state: [:established, :related]
  nft_rule :accept, tcp_dport: 5432
  nft_rule :drop, counter: "api_drop"
end
```

### 2. Forward Rules (which paths between tiers are allowed?)

Explicit rules in the forward chain based on source/destination IPs:

```elixir
# Internet → Nginx: HTTPS only
nft_rule :accept, iifname: "eth0",
  ip_daddr: {:replica_ips, "web", "nginx"}, tcp_dport: 8443

# Nginx → API: internal API calls
nft_rule :accept,
  ip_saddr: {:replica_ips, "web", "nginx"},
  ip_daddr: {:replica_ips, "app", "api"}, tcp_dport: 4000

# API → DB: database queries
nft_rule :accept,
  ip_saddr: {:replica_ips, "app", "api"},
  ip_daddr: {:replica_ips, "data", "postgres"}, tcp_dport: 5432
```

## Monitoring

### Named Counters

```elixir
nft_counter "forward_drop"     # counts drops in forward chain
nft_counter "nginx_drop"       # counts illegal nginx egress

nft_rule :drop, counter: "forward_drop"   # reference in rule
```

erlkoenig polls counters every 2 seconds. When `packets > 0`, an AMQP
event is published:

```
firewall.forward.drop    {"chain":"forward", "packets":42, "pps":21.0, "bytes":2520}
```

### NFLOG (Packet Details)

```elixir
nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
```

Logged packets are captured via NFLOG and published with full header details:

```
firewall.forward.packet  {"src":"10.0.0.2", "dst":"10.0.2.2", "proto":"tcp", "dport":5432}
```

### Connection Tracking

All new and destroyed connections are published:

```
conntrack.flow.new      {"proto":"tcp", "src":"10.0.0.2", "dst":"10.0.1.2", "dport":4000}
conntrack.flow.destroy  {"proto":"tcp", "src":"10.0.0.2", "dst":"10.0.1.2", "dport":4000}
```

## Complete Example

```elixir
nft_table :inet, "erlkoenig" do
  nft_counter "forward_drop"
  nft_counter "web_drop"
  nft_counter "api_drop"
  nft_counter "db_drop"

  base_chain "forward", hook: :forward, type: :filter,
    priority: :filter, policy: :drop do

    nft_rule :accept, ct_state: [:established, :related]

    # Egress filters
    nft_rule :jump, iifname: {:veth_of, "web", "nginx"},    to: "from-web"
    nft_rule :jump, iifname: {:veth_of, "app", "api"},      to: "from-api"
    nft_rule :jump, iifname: {:veth_of, "data", "postgres"}, to: "from-db"

    # Allowed paths
    nft_rule :accept, iifname: "eth0",
      ip_daddr: {:replica_ips, "web", "nginx"}, tcp_dport: 8443
    nft_rule :accept,
      ip_saddr: {:replica_ips, "web", "nginx"},
      ip_daddr: {:replica_ips, "app", "api"}, tcp_dport: 4000
    nft_rule :accept,
      ip_saddr: {:replica_ips, "app", "api"},
      ip_daddr: {:replica_ips, "data", "postgres"}, tcp_dport: 5432

    # Default: drop + count + log
    nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
  end

  nft_chain "from-web" do
    nft_rule :accept, ct_state: [:established, :related]
    nft_rule :accept, tcp_dport: 4000
    nft_rule :drop, counter: "web_drop"
  end

  nft_chain "from-api" do
    nft_rule :accept, ct_state: [:established, :related]
    nft_rule :accept, tcp_dport: 5432
    nft_rule :drop, counter: "api_drop"
  end

  nft_chain "from-db" do
    nft_rule :accept, ct_state: [:established, :related]
    nft_rule :drop, counter: "db_drop"
  end

  base_chain "postrouting", hook: :postrouting, type: :nat,
    priority: :srcnat, policy: :accept do
    nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "dmz"
  end
end
```

## Reactive Threat Detection

erlkoenig monitors conntrack events in real time. Each suspicious source
IP gets its own Erlang process (`erlkoenig_threat_actor`, gen_statem) that
tracks the IP's behavior over time:

```
observing → suspicious → banned → probation → forgotten
```

Bans are applied in the kernel via nft set elements with kernel-side
timeouts. The `erlkoenig_threat_mesh` process is the single source of
truth for all kernel ban operations — actors send intentions, mesh
executes.

### DSL

```elixir
guard do
  detect do
    flood over: 50, within: s(10)
    port_scan over: 20, within: m(1)
    slow_scan over: 5, within: h(1)
    honeypot [21, 22, 23, 445, 1433, 1521, 3306,
              3389, 5900, 6379, 8080, 8888, 9200, 27017]
  end

  respond do
    suspect after: 3, distinct: :ports
    ban_for h(1)
    honeypot_ban_for h(24)
    escalate [h(1), h(6), h(24), d(7)]
    observe_after_unban m(2)
    forget_after m(5)
  end

  allowlist [
    {127, 0, 0, 1},
    {10, 0, 0, 1}
  ]
end
```

Time units: `s()` seconds, `m()` minutes, `h()` hours, `d()` days.

### Detection Types

| Type | Default | What It Catches |
|------|---------|----------------|
| `flood` | 50 connections / 10s | SYN floods, HTTP floods, brute force |
| `port_scan` | 20 distinct ports / 60s | Nmap, Masscan |
| `slow_scan` | 5 distinct ports / 1 hour | Shodan, Censys, manual recon |
| `honeypot` | 1 connection to unused port | Any probe to ports no service uses |

### Per-IP Actor Lifecycle

Each suspicious IP gets its own process with isolated state:

- **observing** — first contact, tracking connections
- **suspicious** — 3+ distinct ports seen, AMQP alert fired
- **banned** — threshold exceeded, kernel-level block active
- **probation** — ban expired, watching for recidivism
- **forgotten** — no traffic for 5 minutes, process dies (automatic cleanup)

Repeat offenders restart with escalated ban durations (1h → 6h → 24h → 7d).

### Architecture

```
Conntrack event → ct_guard (router) → ensure_actor(IP) → threat_actor
                                                              │
                                                    {local_ban, IP, BanUntil}
                                                              │
                                                              ▼
                                                        threat_mesh
                                                              │
                                                    erlkoenig_nft:ban(IP)
                                                              │
                                                              ▼
                                                  Kernel: blocklist set
                                                  (timeout, auto-expiry)
```

The actor never speaks to the kernel directly. This prevents the
micro-unban race where a local timer expiry would briefly open the
firewall while a remote ban is still active.

### AMQP Events

All guard actions publish events to `erlkoenig.events`:

- `guard.threat.ban` — IP banned (reason, duration, ban count)
- `guard.threat.unban` — ban expired
- `guard.threat.honeypot` — honeypot port triggered, instant ban
- `guard.threat.slow_scan` — slow scanner detected
- `guard.threat.suspect` — 3+ ports seen, not yet banned (early warning)
- `guard.threat.ban_failed` — kernel ban attempt failed
- `guard.stats.summary` — periodic stats (actor count, ban count, events/s)

## Data Maps and Verdict Maps

nftables maps are explicit, named lookup tables. The developer defines
them in the DSL — no implicit generation behind the scenes.

### nft_map — Data Map (jhash Loadbalancing)

Maps a hash result to a container IP. Used with `dnat_jhash` for
kernel-native source-IP sticky loadbalancing.

```elixir
nft_map "web_jhash", :mark, :ipv4_addr,
  entries: {:replica_ips, "web", "nginx"}

base_chain "prerouting_nat", hook: :prerouting, type: :nat,
  priority: :dstnat, policy: :accept do
  nft_rule :dnat_jhash,
    iifname: "eth0",
    tcp_dport: 8443,
    map: "web_jhash",
    mod: 3,
    port: 8443
end
```

`:replica_ips` expands at deploy time to the actual container IPs.
`mod: 3` is the jhash modulus (number of map entries). The developer
must set this explicitly — no auto-detection.

Result in the kernel:

```
map web_jhash { type mark : ipv4_addr
    elements = { 0x0 : 10.0.0.2, 0x1 : 10.0.0.3, 0x2 : 10.0.0.4 } }
chain prerouting_nat {
    dnat ip to jhash ip saddr mod 3 seed 0x0 map @web_jhash:8443 }
```

### nft_vmap — Concatenated Verdict Map (Forward Policy)

Replaces multiple accept rules with a single O(1) hashtable lookup.
Composite keys: `ip saddr . ip daddr . tcp dport → verdict`.

```elixir
nft_vmap "fwd_policy",
  fields: [:ipv4_addr, :ipv4_addr, :inet_service],
  entries: [
    {{10, 0, 0, 2}, {10, 0, 1, 2}, 4000, :accept},
    {{10, 0, 0, 3}, {10, 0, 1, 2}, 4000, :accept},
    {{10, 0, 1, 2}, {10, 0, 2, 2}, 5432, :accept}
  ]

base_chain "forward", ... do
  nft_rule :accept, ct_state: [:established, :related]
  nft_rule :vmap_lookup, vmap: "fwd_policy"
  nft_rule :drop, counter: "forward_drop"
end
```

Result in the kernel:

```
map fwd_policy { type ipv4_addr . ipv4_addr . inet_service : verdict
    elements = { 10.0.0.2 . 10.0.1.2 . 4000 : accept,
                 10.0.1.2 . 10.0.2.2 . 5432 : accept } }
chain forward {
    ct state established,related accept
    ip saddr . ip daddr . th dport vmap @fwd_policy
    counter name "forward_drop" drop }
```

At autoscaling time, adding a new container is a single map element
insertion — no rule rebuild needed.
