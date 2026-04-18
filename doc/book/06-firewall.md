# Chapter 6 — Firewall

The firewall lives in the DSL. nftables rules are written as Elixir
blocks inside `host do ... end` or inside a container, compiled to
Netlink batches, and applied atomically. There is no shell, no `nft`
CLI on the hot path, no template expansion: the DSL primitives map
one-to-one onto the kernel primitives.

## Host tables and container tables

Two surfaces exist. The **host table** is shared, visible in the root
network namespace. Its chains hook into `forward`, `input`, `output`,
`prerouting`, `postrouting` at the host level and see every packet
that crosses the host's routing layer. Classic uses: SSH
allow-listing, counting drops per chain, blocking traffic based on
connection state.

The **container table** lives inside a container's own network
namespace, installed at spawn time via `CMD_NFT_SETUP`. Its
`output` and `input` hooks see only that container's traffic. This
is where per-container egress policy belongs. Because L3S places the
netfilter hooks into the container namespace, container tables are
the only layer that can filter traffic between two containers on the
same host.

Host tables are declared inside `host do`; container tables sit inside
a container's `nft` block.

## Base chains and rules

A base chain attaches to a kernel hook. The DSL is explicit about
hook, type, priority, and default policy:

```elixir
nft_table :inet, "host" do
  base_chain "input", hook: :input, type: :filter,
             priority: :filter, policy: :drop do
    nft_rule :accept, ct_state: [:established, :related]
    nft_rule :accept, iifname: "lo"
    nft_rule :accept, tcp_dport: 22, counter: "ssh_accepted"
    nft_rule :drop,   counter: "input_drop"
  end
end
```

Verdicts available on `nft_rule`:

| Verdict            | Meaning                                              |
|--------------------|------------------------------------------------------|
| `:accept`          | pass the packet                                      |
| `:drop`            | silently discard                                     |
| `:reject`          | drop with ICMP unreachable                           |
| `:jump`            | jump to a named chain, continue after return         |
| `:goto`            | transfer control to a chain, no return               |
| `:masquerade`      | SNAT with outbound interface IP                      |
| `:dnat_jhash`      | kernel-native source-IP sticky balancing             |
| `:vmap_lookup`     | jump via a verdict map                               |
| `:flow_offload`    | insert flow into ingress-level fast-path (→ below)   |

Rule predicates cover the usual nft vocabulary: `ct_state`,
`ip_saddr`, `ip_daddr`, `tcp_dport`, `udp_dport`, `iifname`,
`oifname`, `limit`, `log_prefix`, `counter`. The DSL is permissive;
compilation errors are raised with the exact offending term.

## Sets and counters

Sets carry runtime-mutable state — IPs to ban, known peers, allowed
services. A set is declared in the table and referenced from rules:

```elixir
nft_table :inet, "host" do
  nft_set "ban", :ipv4_addr
  nft_counter "input_ban"

  base_chain "prerouting", hook: :prerouting, type: :filter,
             priority: :raw, policy: :accept do
    nft_rule :drop, set: "ban", counter: "input_ban"
  end
end
```

Counters are polled every two seconds. Non-zero rates produce AMQP
events under `firewall.<chain>.drop` (→ Chapter 9). The poll is
cheap: one Netlink request per counter.

A special case: the `"ban"` set is the handle the threat detector
uses to push IPs in and out at runtime (→ Chapter 7). Rules that
drop on `set: "ban"` in a `priority: :raw` chain run before
connection tracking, which is the cheapest possible way to kill a
hostile packet.

## Priorities and hot reload

Chain priority follows the standard nft values: `:raw` at -300 (no
conntrack yet), `:mangle` at -150, `:dstnat` at -100 (prerouting NAT
runs before filter), `:filter` at 0 (the common case), `:security`
at 50, `:srcnat` at 100 (postrouting NAT runs after filter). Lower
values run earlier.

Reloading the firewall is atomic. When the DSL term changes and the
loader calls `erlkoenig_nft_firewall:reload/0`, the module compiles
the new table, wraps everything in a single `NFNL_MSG_BATCH_BEGIN /
BATCH_END` envelope, and hands it to the kernel in one Netlink send.
Either the entire new table appears, or nothing changes. No window
exists where the firewall is half-installed. Conntrack state
survives — the kernel tracks flows independently from the rule set.

## Container firewalls in practice

A container with outbound-only policy — typical for an application
server that talks to a specific database:

```elixir
container "api", binary: "...", zone: "dmz",
  replicas: 2, restart: :permanent do

  nft do
    output do
      nft_rule :accept, ct_state: [:established, :related]
      nft_rule :accept, oifname: "lo"
      nft_rule :accept, ip_daddr: {10, 0, 1, 10}, tcp_dport: 5432  # postgres
      nft_rule :drop, log_prefix: "API: "
    end
  end
end
```

The `output` block compiles to an `output` base chain with `policy:
:drop`. The container can reach the database and nothing else.
Inbound traffic to the container is filtered by the host table or by
absence of a hole in it.

## Runtime services and the operator's responsibility

erlkoenig itself runs services on the host that containers can use —
today that is one service, the per-zone DNS resolver, but the list
will grow as node-resident capabilities land. Every such service
binds on the zone's gateway IP (`.1` of the subnet) on the host
side, and every packet a container sends to it crosses the host's
`input` hook before reaching the BEAM-side socket.

The runtime does **not** silently inject allow rules for its own
services. The operator's `nft_table :inet, "host"` block is the
single source of truth for what reaches the host's input chain. If
that table has `policy: :drop` (which is the recommended hardening
default) and the operator does not explicitly allow the runtime
service's port, that service is unreachable from inside the
container — the container's app will see `getaddrinfo` failures or
connect timeouts, and nothing in `journalctl` will explain why.

This is intentional. The DSL is the contract; magic injection would
make the kernel state diverge from the DSL and turn the system into
a black box. Instead, every operator-grade host firewall block
should carry a clearly-labelled section that mirrors the runtime's
service catalogue:

```elixir
nft_table :inet, "host" do
  base_chain "input", hook: :input, type: :filter,
             priority: :filter, policy: :drop do

    # ── Standard hardening ───────────────────────────────────
    nft_rule :accept, ct_state: [:established, :related]
    nft_rule :accept, iifname: "lo"
    nft_rule :accept, ip_protocol: :icmp
    nft_rule :accept, tcp_dport: 22                # SSH
    nft_rule :accept, tcp_dport: 9100              # node_exporter

    # ── Runtime services ────────────────────────────────────
    # erlkoenig runs a DNS resolver on each zone's gateway IP.
    # Without this rule, /etc/resolv.conf inside containers
    # points at an unreachable address and every getaddrinfo()
    # call times out.
    nft_rule :accept, ip_saddr: {10, 0, 0, 0, 24}, udp_dport: 53
  end
end
```

The `ip_saddr` predicate restricts the allow to packets coming from
inside the zone — outside hosts that could otherwise abuse the
resolver are still dropped by the chain policy.

### Service catalogue

| Service        | Bind address       | Port    | Operator rule template                                              |
|----------------|--------------------|---------|----------------------------------------------------------------------|
| Zone DNS       | zone gateway IP    | UDP/53  | `:accept, ip_saddr: <zone-subnet-cidr>, udp_dport: 53`             |

Future capabilities (postgres.local, journal.local, blob.local —
see the strategy memo in `doc/strategy/`) will extend this table
with their own ports. The pattern stays the same: one row per
service, rule template uses the zone subnet as `ip_saddr` to
restrict access, the operator copies the row into the host table.

## erlkoenig as a standalone host firewall

You do not need to run containers to benefit from erlkoenig's firewall.
A stack file that only declares `host do ... end` with an `nft_table`
block is a complete, atomic, hot-reloadable nftables policy managed
from a single Elixir file. Every rule compiles to raw Netlink — no
`nft` binary on the system, no shell escaping, no iptables-nft
translation layer.

The following examples show real-world host-firewall configurations.
Each one is a self-contained stack file. Load with `ek up <file>`,
inspect with `nft list ruleset`, reload with `ek reload`.

### Web server

A public-facing web server that accepts SSH, HTTP, HTTPS, and
nothing else. SSH is rate-limited to slow brute-force attempts.
Every dropped packet is logged and counted.

```elixir
defmodule WebServer do
  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    nft_table :inet, "host" do
      nft_counter "ssh_accepted"
      nft_counter "http_accepted"
      nft_counter "input_drop"

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        # ── Stateful baseline ───────────────────────────────
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp

        # ── SSH: rate-limited to 5 new connections / minute ─
        nft_rule :accept, tcp_dport: 22, counter: "ssh_accepted",
                          limit: %{rate: 5, burst: 10}

        # ── Web traffic ─────────────────────────────────────
        nft_rule :accept, tcp_dport: 80, counter: "http_accepted"
        nft_rule :accept, tcp_dport: 443

        # ── Default: drop + log ─────────────────────────────
        nft_rule :drop, log_prefix: "INPUT: ", counter: "input_drop"
      end
    end
  end
end
```

The `limit` predicate uses the kernel's token-bucket rate limiter.
Connections beyond the limit hit the chain's default policy (`:drop`).
Legitimate users who already have an established SSH session are
unaffected — their packets match `ct_state: [:established, :related]`
before the rate-limited rule.

### Database server

A PostgreSQL server that only accepts connections from two known
application servers. No outbound connections are allowed — a
compromised database cannot phone home.

```elixir
defmodule DatabaseServer do
  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    nft_table :inet, "host" do
      nft_set "app_servers", :ipv4_addr
      nft_counter "pg_accepted"
      nft_counter "input_drop"
      nft_counter "output_drop"

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22,
                          ip_saddr: {10, 0, 1, 0, 24}  # management VLAN

        # ── PostgreSQL: only from app servers ───────────────
        nft_rule :accept, tcp_dport: 5432,
                          set: "app_servers",
                          counter: "pg_accepted"

        nft_rule :drop, log_prefix: "DB-IN: ", counter: "input_drop"
      end

      # ── Outbound lockdown ─────────────────────────────────
      # The database must never initiate connections. Responses
      # to accepted inbound connections flow through established/
      # related; everything else is blocked.
      base_chain "output", hook: :output, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, oifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, udp_dport: 53   # DNS for pg_hba hostname checks

        nft_rule :drop, log_prefix: "DB-OUT: ", counter: "output_drop"
      end
    end
  end
end
```

The `"app_servers"` set starts empty. Populate it at runtime via the
erlkoenig control API or the threat detector's set interface:

    ek nft set add host app_servers 10.0.2.5
    ek nft set add host app_servers 10.0.2.6

Removing an app server from the set immediately blocks new connections
from that IP. Existing connections drain naturally through conntrack.

### Bastion host

A jump host that allows SSH only from a corporate CIDR. The bastion
itself must not initiate connections to the internet — only to the
internal network behind it. SSH agent forwarding and ProxyJump work
because they ride the established connection.

```elixir
defmodule Bastion do
  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    nft_table :inet, "host" do
      nft_counter "ssh_office"
      nft_counter "ssh_rejected"
      nft_counter "forward_drop"

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp

        # ── SSH: only from office ───────────────────────────
        nft_rule :accept, tcp_dport: 22,
                          ip_saddr: {203, 0, 113, 0, 24},
                          counter: "ssh_office"

        # Explicit reject for SSH from everywhere else —
        # gives the user a clear "connection refused" instead
        # of a silent timeout.
        nft_rule :reject, tcp_dport: 22, counter: "ssh_rejected"

        nft_rule :drop, log_prefix: "BASTION: "
      end

      # ── No forwarding through the bastion ─────────────────
      base_chain "forward", hook: :forward, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :drop, counter: "forward_drop"
      end
    end
  end
end
```

The `:reject` verdict sends an ICMP port-unreachable back to the
client. This is a deliberate choice: SSH clients get a fast failure
instead of waiting for the TCP handshake to time out. For internet-
facing services where you want stealth, use `:drop` instead.

### NAT gateway with masquerade

A gateway that NATs a private subnet (`10.0.0.0/16`) to the internet
via `eth0`. Internal machines use this host as their default route.
The prerouting chain does reverse-path filtering to catch spoofed
source addresses.

```elixir
defmodule NatGateway do
  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    nft_table :inet, "host" do
      nft_counter "nat_masq"
      nft_counter "forward_drop"

      # ── Input: standard hardened host ─────────────────────
      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22,
                          ip_saddr: {10, 0, 0, 0, 16}

        nft_rule :drop, log_prefix: "GW-IN: "
      end

      # ── Forward: allow internal → internet, block reverse ─
      base_chain "forward", hook: :forward, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 16},
                          oifname: "eth0"

        nft_rule :drop, log_prefix: "GW-FWD: ",
                        counter: "forward_drop"
      end

      # ── Postrouting: masquerade outbound traffic ──────────
      base_chain "postrouting", hook: :postrouting, type: :nat,
                 priority: :srcnat, policy: :accept do

        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 16},
                              oifname: "eth0"
      end

      # ── Prerouting: anti-spoofing ─────────────────────────
      base_chain "prerouting", hook: :prerouting, type: :filter,
                 priority: :raw, policy: :accept do

        nft_rule :fib_rpf
      end
    end
  end
end
```

The `:fib_rpf` verdict is a kernel-native reverse-path check. If a
packet arrives on an interface that the kernel would not use to route
back to the source address, the packet is dropped. This catches the
most common spoofing patterns at zero application cost.

### Ban set with early drop

The cheapest possible packet kill: drop banned IPs before connection
tracking even sees them. This is how erlkoenig's threat detector
works under the hood (→ Chapter 7), but the pattern is useful
standalone for manual IP blocking.

```elixir
nft_table :inet, "host" do
  nft_set "ban", :ipv4_addr
  nft_counter "ban_drop"

  # priority: :raw runs at -300, before conntrack.
  # No connection state is created for banned IPs.
  base_chain "prerouting", hook: :prerouting, type: :filter,
             priority: :raw, policy: :accept do

    nft_rule :drop, set: "ban", counter: "ban_drop"
  end

  # ... input chain follows at priority: :filter ...
end
```

At `priority: :raw`, the kernel has not yet allocated a conntrack
entry for the packet. Dropping here is measurably cheaper than
dropping at `:filter` — the kernel saves the conntrack hash lookup,
the memory allocation for the flow entry, and the eventual timeout
cleanup. On a host under DDoS, this difference matters.

## Inter-container network policy

With IPVLAN L3S, containers share the host's physical network but
each has its own network namespace with its own netfilter hooks.

**Critical L3S property:** traffic between two containers on the
same IPVLAN parent bypasses the host's `forward` chain entirely.
The ipvlan driver fast-paths packets from one slave to another via
`ipvlan_l3_rcv()` without traversing the host's full network stack.
The host never sees these packets in its netfilter hooks.

This means the **container-local nft table is the sole enforcement
point** for same-zone inter-container traffic. A packet from
container A to container B on the same parent passes only through:

1. A's `output` chain (inside A's namespace)
2. B's `input` chain (inside B's namespace)

No host-level chain participates. If neither container has nft
rules, everything flows freely between them regardless of what the
host's forward chain says. This is the fundamental reason per-
container nft rules exist — without them, zone-mates have
unrestricted L3 access to each other.

For traffic that crosses zone boundaries (different parents) or
leaves the host entirely, the host's `forward` chain does apply.
Defense-in-depth forward rules are still useful for those paths.

### Zero-trust: deny-all, allow explicit

The strongest inter-container posture: every container drops
everything by default and explicitly lists what it may reach. The
host forward chain mirrors the same policy.

```elixir
pod "app", strategy: :one_for_one do
  # ── Worker: may only talk to the cache on port 6379 ─────
  container "worker",
    binary: "/opt/app/worker",
    zone: "app-net",
    replicas: 4, restart: :permanent do

    nft do
      output policy: :drop do
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, ip_daddr: {10, 0, 0, 10},
                          tcp_dport: 6379
      end
      input policy: :drop do
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ct_state: [:established, :related]
      end
    end
  end

  # ── Cache: accepts connections from workers, nothing else ─
  container "cache",
    binary: "/opt/app/redis-server",
    zone: "app-net",
    replicas: 1, restart: :permanent do

    nft do
      output policy: :drop do
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ct_state: [:established, :related]
      end
      input policy: :drop do
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 24},
                          tcp_dport: 6379
      end
    end
  end
end
```

The worker's output chain allows exactly one destination (the cache
on port 6379). The cache's input chain allows exactly one service
port from the zone subnet. A compromised worker cannot reach the
database, cannot scan the local network, cannot exfiltrate data to
the internet — the kernel drops the packet before it leaves the
namespace.

### Three-tier with per-container enforcement

The real enforcement for same-zone traffic happens inside each
container's namespace. This is the model from
`examples/three_tier_ipvlan_fw.exs`: three tiers of containers
(web, app, data), each with their own output and input chains that
declare exactly what they may send and receive.

The web containers may only reach the app server on port 4000:

```elixir
container "nginx", binary: "...", zone: "containers",
  replicas: 3, restart: :permanent do

  nft do
    output policy: :drop do
      nft_rule :accept, iifname: "lo"
      nft_rule :accept, ct_state: [:established, :related]
      nft_rule :accept, ip_daddr: {10, 50, 100, 5}, tcp_dport: 4000
    end
    input policy: :drop do
      nft_rule :accept, iifname: "lo"
      nft_rule :accept, ct_state: [:established, :related]
      nft_rule :accept, tcp_dport: 8443
    end
  end
end
```

The postgres container may not initiate any connections at all:

```elixir
container "postgres", binary: "...", zone: "containers",
  replicas: 1, restart: :permanent do

  nft do
    output policy: :drop do
      nft_rule :accept, iifname: "lo"
      nft_rule :accept, ct_state: [:established, :related]
    end
    input policy: :drop do
      nft_rule :accept, iifname: "lo"
      nft_rule :accept, ct_state: [:established, :related]
      nft_rule :accept, ip_saddr: {10, 50, 100, 5}, tcp_dport: 5432
    end
  end
end
```

The result: web cannot reach postgres directly (web's output chain
only allows the app's IP). Postgres cannot exfiltrate data (its
output chain drops everything except replies). Every tier boundary
is enforced inside the container's own namespace, exactly where
IPVLAN L3S places the netfilter hooks.

**Why not a host forward chain?** Containers on the same IPVLAN
parent share a zone. Traffic between them is fast-pathed by the
ipvlan driver and never reaches the host's `forward` hook. A host-
level forward chain would only fire for traffic that crosses zone
boundaries (different parents) or leaves the host entirely. For
same-zone enforcement, the container's own nft table is the only
layer that works.

The `examples/three_tier_ipvlan_fw.exs` file includes both per-
container rules and a host-level forward chain as defense-in-depth.
The host forward chain catches cross-zone paths; the container
rules handle same-zone paths. The full example is in the
`examples/` directory.

The IP addresses are deterministic: erlkoenig assigns container
IPs from the zone's subnet pool starting at `.2`, in the order the
containers are declared in the stack file.

## Fast-path offload with flowtables

For throughput-heavy workloads a full chain traversal on every
packet is expensive. nftables offers a native fast-path: the
**flowtable**. Once a connection is established, the kernel
records the flow in an ingress-level lookup table and short-
circuits subsequent packets straight from the network device to
its egress peer — no chain evaluation, no ct-state lookup, no
rule iteration. This is the same class of optimization as eBPF-
based acceleration (XDP, Cilium's fast-path) but without any
userspace toolchain, BPF objects, or kernel helpers — just
nftables primitives the operator already knows.

### Declaring a flowtable

A flowtable is declared inside an `nft_table` block and attached
to one or more network devices. Rules then opt specific flows
into offloading:

```elixir
host do
  interface "eth0", zone: :wan

  nft_table :inet, "filter" do
    nft_flowtable "ft0", devices: ["eth0"]

    base_chain "forward", hook: :forward, type: :filter,
               priority: :filter, policy: :drop do

      # Established flows: fast-path, skip the rest of the chain
      nft_rule :flow_offload, flowtable: "ft0"

      # Policy for new connections (first packet of every flow)
      nft_rule :accept, ct_state: [:established, :related]
      nft_rule :accept, ip_saddr: {10, 0, 0, 0, 16}
      nft_rule :drop, log_prefix: "FWD: "
    end
  end
end
```

Two predicates make this work:

- **`nft_flowtable "ft0", devices: ["eth0"]`** — declares the
  flowtable, hooks it at ingress on `eth0`. Multiple devices are
  allowed; all of them participate in the fast-path.
- **`nft_rule :flow_offload, flowtable: "ft0"`** — inserts a
  rule that matches `ct state established` and offloads the flow
  into the named flowtable. Compiles to
  `ct state established flow add @ft0`.

### How it actually runs

The first packet of a connection traverses the full chain (for
policy evaluation). If that packet matches the `:flow_offload`
rule — which also requires `ct state established`, so the
3-way handshake must be past — the kernel writes the flow tuple
(5-tuple + next-hop) into the flowtable at the ingress hook.

Every subsequent packet on that flow is caught by the ingress
hook before the main stack sees it. The kernel rewrites the
destination MAC, decrements TTL, and forwards directly to the
egress device. No `forward` chain, no `postrouting` chain, no
conntrack state updates beyond a liveness timer.

The speedup is proportional to chain depth. A simple chain gains
little; a three-tier enforcement stack with counters, logs, and
set lookups gains a lot — exactly the workloads where the
fast-path matters.

### Constraints

Flowtables are not a drop-in replacement for every forward
rule. Flows that the kernel cannot offload (or un-offloads mid-
stream) automatically fall back to full chain evaluation:

- Only TCP and UDP flows are eligible.
- NAT that rewrites addresses or ports after offload is not
  supported — the flow is evicted when the kernel detects the
  mismatch.
- L7 inspection (NFQUEUE, logging per-packet) must not be in
  the forward path for offloaded flows.
- IPVLAN *slave* interfaces cannot be flowtable devices directly
  (they share the parent's ingress); attach the flowtable to the
  IPVLAN parent or to the physical device.
- Hardware offload (`flags: hw_offload`) requires a NIC that
  exposes the `flow_offload` driver hook. Without it, the
  flowtable still works in software — the ingress shortcut alone
  is the main win.

### Observing the fast-path

`nft list table inet filter` shows the flowtable and the offload
rule. To observe flows actually being offloaded, watch the
flow-table contents directly:

    nft list flowtables
    nft monitor flows

Under sustained traffic, the forward chain's counters grow only
during connection setup; the flowtable carries the bulk. A
`counter` on the `:flow_offload` rule shows how many flows ever
entered the fast-path — a useful diagnostic.

The full working example is in `examples/fw_flowtable.exs`.

### Reading the counters

Every named counter is polled by the runtime and published as an
AMQP event (→ Chapter 9). But you can also read them directly:

    $ ek nft counters
    ban_drop       packets: 4271   bytes: 213550
    input_drop     packets: 89     bytes: 4628
    forward_drop   packets: 0      bytes: 0
    ssh_accepted   packets: 1203   bytes: 96240

Non-zero `forward_drop` means someone tried a path that the policy
blocks. Non-zero `ban_drop` means the threat detector is actively
working. Zero `forward_drop` over weeks of operation means the
container topology matches the policy — the system is clean.

## What this chapter links to

- The `set: "ban"` handle maps to threat detection → Chapter 7.
- Counter events on the wire → Chapter 9.
- How the firewall actually reaches the kernel (Netlink batches,
  drain-and-ack discipline) → Chapter 14.
