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
