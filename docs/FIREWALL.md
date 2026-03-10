# Firewall Engine

How ~10,000 lines of pure Erlang replace `nft`, `iptables`, and every
firewall CLI tool — by speaking the kernel's own language.

## The Netlink Stack

The entire engine rests on one socket call:

```erlang
socket:open(16, raw, 12)    %% AF_NETLINK = 16, NETLINK_NETFILTER = 12
```

This opens a raw netlink socket to the kernel's nf_tables subsystem.
Every operation — creating tables, chains, sets, rules, counters — is a
binary message sent over this socket. No subprocess. No NIF. No C code.

### Message Format

Every netlink message has a 20-byte header:

```
nlmsghdr (16 bytes, little-endian):
  Length:32    Total message length (headers + payload + padding)
  Type:16     (Subsystem << 8) | MessageType
  Flags:16    NLM_F_REQUEST, NLM_F_CREATE, NLM_F_ACK, ...
  Seq:32      Request-response correlation
  PortId:32   Source port (0 = kernel)

nfgenmsg (4 bytes):
  Family:8    1=inet, 2=ipv4, 10=ipv6
  Version:8   Always 0
  ResId:16    Subsystem-specific
```

Attributes use TLV encoding with 4-byte alignment:

```
<<Length:16/little, Type:16/little, Data/binary, Padding/binary>>
```

Headers are little-endian (Linux convention). Data values inside
expressions are big-endian (network byte order). Getting this wrong
produces rules that silently match nothing. The encoder handles it
so you don't have to.

### Atomic Batches

All kernel changes go through batch transactions:

```
batch_begin(Seq)
  NFT_MSG_NEWTABLE  (create table)
  NFT_MSG_NEWCHAIN  (create chain with policy)
  NFT_MSG_NEWCHAIN  (create another chain)
  NFT_MSG_NEWRULE   (add rule to chain)
  NFT_MSG_NEWRULE   (add another rule)
  ...
batch_end(Seq + N + 1)
```

The kernel applies all messages atomically. If any message fails
(invalid expression, missing chain, permission denied), the entire
batch is rolled back. No partial state. No torn rule sets.

`nfnl_server` manages the shared socket, assigns sequence numbers,
collects ACK/error responses, and returns `ok` or
`{error, {Code, Name}}` (e.g., `{-22, einval}`).

## Expression IR

Rules are not built as netlink bytes directly. They are built as
semantic terms — an intermediate representation that both the kernel
encoder and the test simulator understand.

```erlang
%% A rate-limited SSH accept rule:
[
  meta(l4proto, 1),                          %% load protocol into reg1
  cmp(eq, 1, <<6>>),                         %% reg1 == TCP?
  payload(transport, 2, 2, 1),               %% load dport into reg1
  cmp(eq, 1, <<22:16/big>>),                 %% reg1 == 22?
  limit(25, 5),                              %% 25/s, burst 5
  objref_counter(<<"ssh">>),                 %% increment named counter
  accept()                                   %% verdict: accept
]
```

Each term is a tuple like `{meta, #{key => l4proto, dreg => 1}}`.
The IR has five categories:

**Producers** load data into registers:
`payload`, `meta`, `ct` (conntrack state)

**Consumers** test register values:
`cmp`, `range`, `bitwise`, `lookup` (set membership)

**Actions** produce side effects:
`counter`, `objref_counter`, `log`, `limit`, `dynset`

**Terminals** set the verdict:
`accept`, `drop`, `reject`, `jump`, `goto`, `return`

**NAT**:
`snat`, `dnat`, `masq`, `redir`

Evaluation is left-to-right. Any failing test produces a BREAK —
skip the rest of this rule, try the next one. This matches the
kernel's `nft_do_chain()` semantics exactly.

## Code Generation

38 of the 83 modules are generated from the kernel header
`nf_tables.h`. An escript (`codegen/nft_gen.escript`) parses the
enum declarations:

```c
enum nft_payload_attributes {
    NFTA_PAYLOAD_UNSPEC,
    NFTA_PAYLOAD_DREG,      /* NLA_U32 */
    NFTA_PAYLOAD_BASE,      /* NLA_U32 */
    NFTA_PAYLOAD_OFFSET,    /* NLA_U32 */
    NFTA_PAYLOAD_LEN,       /* NLA_U32 */
    ...
};
```

And emits `nft_expr_payload_gen.erl`:

```erlang
encode(Opts) ->
    Attrs = maps:fold(fun encode_attr/3, [], Opts),
    nft_expr:build(<<"payload">>, iolist_to_binary(Attrs)).

encode_attr(dreg, V, Acc)   -> [nfnl_attr:encode_u32(?NFTA_PAYLOAD_DREG, V) | Acc];
encode_attr(base, V, Acc)   -> [nfnl_attr:encode_u32(?NFTA_PAYLOAD_BASE, V) | Acc];
encode_attr(offset, V, Acc) -> [nfnl_attr:encode_u32(?NFTA_PAYLOAD_OFFSET, V) | Acc];
...
```

One module per expression type. Encode and decode. The generator
handles the boilerplate; all semantic logic is hand-written.

**Stats:** 45 hand-written modules (7,909 LOC), 38 generated (2,088 LOC).
The codegen ratio is ~21% — enough to eliminate structural
boilerplate without hiding domain logic.

## Rule Builders

`nft_rules` provides a semantic API for common firewall patterns.
Each function returns a list of IR terms ready for encoding or
simulation:

```erlang
ct_established_accept()                    %% conntrack established+related
iif_accept()                               %% accept on loopback
tcp_accept(80, http)                       %% TCP port + named counter
tcp_accept_limited(22, ssh, #{rate => 25}) %% rate-limited (two rules)
set_lookup_drop(<<"blocklist">>)           %% drop if source IP in set
log_drop_nflog(<<"DROP: ">>, 1, dropped)   %% NFLOG + counter + drop
masq_rule()                                %% masquerade (dynamic SNAT)
dnat_rule(IP, Port)                        %% destination NAT
```

Rate-limited rules are interesting — they expand to *two* kernel rules:

1. Match port + `limit_over(Rate, Burst)` + `drop` — drop excess traffic
2. Match port + `counter` + `accept` — accept the rest

This is how nf_tables rate limiting works. The semantic API hides it.

## Kernel Emulator

`nft_vm` replicates the kernel's rule evaluation engine in pure Erlang.
16 data registers, 1 verdict register, left-to-right expression
evaluation with BREAK semantics.

```erlang
Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,5}, dport => 22}),
Rules = nft_rules:tcp_accept(22, ssh),
{accept, Trace} = nft_vm:eval(Rules, Pkt, drop).
```

The emulator returns a trace — every expression step with register
state before and after. You can see exactly why a packet was accepted
or dropped, which rule matched, and at which expression the decision
was made.

**Chain evaluation** mirrors `nft_do_chain()`:
1. Try rule 1. If all expressions pass → apply verdict (accept/drop).
   If any expression BREAKs → skip to rule 2.
2. Try rule 2. Same logic.
3. If no rule matched → apply chain's default policy.

129 tests run through this emulator. Every rule template in
`nft_rules` has test coverage. Rules are verified in userspace
before they ever touch the kernel.

## Conntrack Monitor

`erlkoenig_nft_ct` opens a second netlink socket subscribed to conntrack
multicast groups:

- `NFNLGRP_CONNTRACK_NEW` — new connection events
- `NFNLGRP_CONNTRACK_DESTROY` — connection termination

Every TCP SYN, every UDP flow, every ICMP exchange — the kernel
reports it, and Erlang parses the netlink message into a map:

```erlang
{ct_new, #{proto => tcp, src => {203,0,113,42}, dst => {10,0,0,1},
           sport => 54321, dport => 22}}
```

Events are broadcast via `pg` process groups. Any process can
subscribe to `ct_events` and react.

### Dual-Mode Tracking

Under normal load, `erlkoenig_nft_ct` tracks every connection individually
in ETS (~100 bytes per connection). Under DDoS, it automatically
switches to per-source-IP aggregation (~10 bytes per source).
Memory drops 10x without losing threat visibility.

The switch is automatic. When the connection count exceeds
`max_entries`, full tracking stops and aggregate counters take over.
When the attack subsides, it switches back.

## Threat Detection

`erlkoenig_nft_ct_guard` subscribes to conntrack events and watches for
two attack patterns:

**Connection flood:** More than N connections from one source IP
within T seconds. Detects SYN floods, HTTP floods, brute-force
login attempts. Default: 50 connections in 10 seconds.

**Port scan:** Connections to more than M distinct destination
ports from one source within T seconds. Detects port scanners
and vulnerability probes. Default: 20 ports in 60 seconds.

Detection uses a sliding window in ETS. Each new connection is
an `{SrcIP, Timestamp, DstPort}` entry. A periodic timer cleans
entries older than the window. When a threshold is exceeded:

1. Add the source IP to the nf_tables blocklist set
2. Record the ban in ETS with expiry time
3. Start a timer for automatic unban

Bans are temporary (default: 1 hour). When the timer fires,
the IP is removed from the kernel set. No manual intervention.

Whitelisted IPs (loopback, admin addresses) are never banned.

```erlang
erlkoenig_nft:guard_stats().
%% => #{floods_detected => 3, scans_detected => 1, active_bans => 2}

erlkoenig_nft:guard_banned().
%% => [#{ip => "203.0.113.42", reason => conn_flood, expires_in => 2847}]
```

## Set-Based Banning

When you call `ban("203.0.113.42")`, the IP is not added as a new
firewall rule. It's added as an element to an nf_tables *set* — a
kernel hash table with O(1) lookup.

The set is created at startup:

```erlang
nft_set:add(Seq, Family, Table, <<"blocklist">>, ipv4_addr)
```

A single rule references the set:

```erlang
set_lookup_drop(<<"blocklist">>)
%% → ip saddr @blocklist drop
```

Banning adds a set element via netlink:

```erlang
nft_set_elem:add(Seq, Family, Table, <<"blocklist">>, <<10,0,0,5:32>>)
```

One rule handles all bans. Ban 1 IP or 100,000 — the kernel does
a hash lookup, not a linear scan. Ban/unban takes microseconds
and doesn't touch the rule chain at all.

## Counter Monitoring

Named counters are nf_tables objects that track packet counts
and byte counts per rule. `erlkoenig_nft_counter` workers poll each counter
at a configurable interval and calculate rates:

```erlang
erlkoenig_nft:rates().
%% => #{ssh => #{pps => 12.5, bps => 8340.0},
%%       http => #{pps => 245.0, bps => 198400.0},
%%       dropped => #{pps => 0.5, bps => 320.0}}
```

Threshold alerts fire when a rate exceeds a configured value.
Events are broadcast via `pg` — subscribe and build your own
alerting, dashboards, or adaptive responses.

## NFLOG

Rules can log packets via NFLOG instead of kernel `printk`.
`erlkoenig_nft_nflog` opens a netlink socket subscribed to the NFLOG
multicast group and parses incoming packets:

```erlang
{nflog_event, #{prefix => <<"ERLKOENIG: ">>,
                src => <<"203.0.113.42">>, dst => <<"10.0.0.1">>,
                proto => <<"tcp">>, sport => 54321, dport => 443}}
```

Parsed in Erlang, broadcast via `pg`. No syslog, no file I/O,
no `ulogd`. The BEAM *is* the log processor.

## Supervision Tree

```
erlkoenig_nft_sup (rest_for_one)
│
├── pg (erlkoenig_nft)          Process groups for event broadcast
├── nfnl_server                 Shared netlink socket
├── erlkoenig_nft_nflog                  NFLOG packet receiver
├── erlkoenig_nft_ct                     Conntrack monitor (multicast)
├── erlkoenig_nft_ct_guard               Threat detection + auto-ban
├── erlkoenig_nft_watch_sup              Dynamic counter supervisor
│   └── erlkoenig_nft_counter            One worker per named counter
└── erlkoenig_nft_firewall               Config owner, rule lifecycle
```

**`rest_for_one`**: If the netlink socket crashes, everything
downstream restarts — they all depend on it. But `pg` at the
top stays alive, so event subscribers don't lose their group
membership.

**`erlkoenig_nft_firewall` last**: It depends on `nfnl_server` (to send
rules) and `erlkoenig_nft_ct_guard` (to register ban callbacks). Starting
it last ensures all dependencies are ready.

**Crash recovery**: If `erlkoenig_nft_ct` crashes, it reopens the
conntrack multicast socket and resumes — in-kernel connections
are unaffected. If `erlkoenig_nft_firewall` crashes, it re-reads the
config and re-applies all rules via a fresh batch transaction.
The kernel's atomic batches mean rules are either fully applied
or not at all.

## Configuration

The entire firewall is defined in a single Erlang term file:

```erlang
#{
    table => <<"erlkoenig">>,
    sets => [
        {<<"blocklist">>, ipv4_addr},
        {<<"blocklist6">>, ipv6_addr}
    ],
    counters => [ssh, http, https, banned, dropped],
    chains => [
        #{name => <<"input">>, hook => input, type => filter,
          priority => 0, policy => drop,
          rules => [
              ct_established_accept,
              iif_accept,
              {tcp_accept_limited, 22, ssh, #{rate => 25, burst => 5}},
              {tcp_accept, 80, http},
              {tcp_accept, 443, https},
              {protocol_accept, icmp},
              {log_drop_nflog, <<"ERLKOENIG: ">>, 1, dropped}
          ]}
    ],
    watch => #{
        interval => 2000,
        thresholds => [
            {ssh_flood, ssh, pps, '>', 50.0},
            {http_flood, http, pps, '>', 500.0}
        ]
    },
    ct_guard => #{
        conn_flood => {50, 10},
        port_scan  => {20, 60},
        ban_duration => 3600
    }
}.
```

`reload/0` re-applies the config as a new batch transaction.
No connections dropped. No rule gaps. The kernel switches from
the old ruleset to the new one in a single atomic operation.

## Elixir DSL

Nobody wants to write nested Erlang maps by hand. The Elixir DSL
compiles to the exact same `.term` format — but reads like a
firewall config should:

```elixir
defmodule MyFirewall do
  use Erlkoenig.Firewall

  firewall "production" do
    counters [:ssh, :http, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3600

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept :icmp
      accept_tcp 22, counter: :ssh, limit: {25, burst: 5}
      accept_tcp [80, 443], counter: :http
      drop_if_in_set "blocklist", counter: :dropped
      log_and_drop "BLOCKED: "
    end
  end

  guard do
    detect :conn_flood, threshold: 50, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 3600
    whitelist {10, 0, 0, 1}
  end
end
```

Compare that to the equivalent Erlang term above. Same semantics,
same output — but `accept_tcp 22, counter: :ssh, limit: {25, burst: 5}`
is immediately obvious. No binary syntax, no nested maps, no
angle brackets.

The DSL is compiled at build time by an escript (1.4 MB, needs only
`erl`, no Elixir runtime). It validates IP conflicts, duplicate ports,
and missing fields before producing the `.term` file. The runtime
never sees Elixir — it loads a plain Erlang term.

## Source Map

### Netlink Protocol Stack

| Module | LOC | Role |
|--------|-----|------|
| `nfnl_socket` | ~120 | `socket:open(16, raw, 12)`, send/recv |
| `nfnl_msg` | ~130 | nlmsghdr + nfgenmsg construction |
| `nfnl_attr` | ~180 | TLV attribute encoding/decoding |
| `nfnl_server` | ~250 | Supervised socket, batch transactions |
| `nfnl_response` | ~100 | ACK/error response parsing |

### Rule Engine

| Module | LOC | Role |
|--------|-----|------|
| `nft_expr_ir` | ~500 | Intermediate representation (50+ expr types) |
| `nft_encode` | ~350 | IR → netlink binary |
| `nft_rules` | ~500 | Semantic rule builders |
| `nft_vm` | ~600 | Kernel emulator (16 registers, BREAK semantics) |
| `nft_vm_pkt` | ~300 | Synthetic packet builder |
| `nft_expr_*_gen` | 2,088 | 38 generated attribute encoders |

### Monitoring

| Module | LOC | Role |
|--------|-----|------|
| `erlkoenig_nft_firewall` | ~550 | Config lifecycle, ban/unban, reload |
| `erlkoenig_nft_ct` | ~500 | Conntrack multicast, dual-mode tracking |
| `erlkoenig_nft_ct_guard` | ~400 | Flood/scan detection, auto-ban |
| `erlkoenig_nft_counter` | ~200 | Per-counter polling + rate calculation |
| `erlkoenig_nft_nflog` | ~200 | NFLOG packet parsing |

### Object Operations

| Module | Role |
|--------|------|
| `nft_table` | Table creation/deletion |
| `nft_chain` | Chain creation with hooks and policies |
| `nft_rule` | Rule addition (expression list → NEWRULE) |
| `nft_set` | Set management (blocklists, allowlists) |
| `nft_set_elem` | Set element add/delete (ban/unban) |
| `nft_object` | Named counter/quota objects |
| `nft_delete` | Bulk deletion |
| `nft_query` | Kernel rule/chain/table dumps |
| `nft_decode` | Netlink → human-readable rule strings |
