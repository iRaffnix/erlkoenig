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
conntrack yet), `:filter` at 0 (the common case), `:srcnat` at -100,
`:dstnat` at 100. Lower values run earlier.

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

## What this chapter links to

- The `set: "ban"` handle maps to threat detection → Chapter 7.
- Counter events on the wire → Chapter 9.
- How the firewall actually reaches the kernel (Netlink batches,
  drain-and-ack discipline) → Chapter 14.
