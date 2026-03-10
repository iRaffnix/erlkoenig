# erlkoenig_nft

A firewall engine written in pure Erlang that talks directly to the Linux kernel.

```erlang
erlkoenig_nft:ban("203.0.113.42").
```

One function call. The IP is blocked in microseconds — inserted into a kernel
hash set via AF_NETLINK, no subprocess, no CLI tool, no NIF. When the ban
expires, an Erlang timer removes it automatically.

## How it works

`erlkoenig_nft` speaks the nf_tables netlink protocol natively:

```
socket:open(16, raw, 12)     %% AF_NETLINK, NETLINK_NETFILTER
```

Every nf_tables operation — creating tables, chains, sets, rules, counters —
is a binary message sent over this socket. The entire netlink stack is pure
Erlang: message framing, TLV attribute encoding, batch transactions.
38 expression encoders are code-generated from the kernel's `nf_tables.h`.

No C code. No NIFs. No `os:cmd("nft ...")`. Zero external dependencies
beyond OTP 27.

## What you get

```erlang
%% Host firewall from a single config file
erlkoenig_nft:status().
erlkoenig_nft:reload().

%% Runtime IP blocking (kernel hash set, O(1) lookup)
erlkoenig_nft:ban("10.0.0.5").
erlkoenig_nft:unban("10.0.0.5").

%% Live packet/byte counters with threshold alerts
erlkoenig_nft:rates().

%% Connection tracking via netlink multicast
erlkoenig_nft:ct_count().
erlkoenig_nft:ct_top(10).       %% top 10 source IPs

%% Automatic threat detection
erlkoenig_nft:guard_stats().
%% => #{floods_detected => 3, scans_detected => 1, active_bans => 2}
```

**Threat detection** watches connection patterns in real time. Flood an SSH
port? 50 connections in 10 seconds triggers an automatic ban. Scan 20 ports
in a minute? Banned. All configurable, all with automatic expiry.

**Live counters** track packet rates per rule. Set thresholds, get alerts
when traffic spikes. No Prometheus needed for basic monitoring.

**Conntrack monitoring** subscribes to kernel multicast groups
(`NFNLGRP_CONNTRACK_NEW`, `NFNLGRP_CONNTRACK_DESTROY`) — the same feed
that `conntrack -E` reads, but parsed in pure Erlang.

## Configuration

The firewall is defined in a single Erlang term file:

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
    ct_guard => #{
        conn_flood => {50, 10},     %% 50 conns in 10s → ban
        port_scan  => {20, 60},     %% 20 ports in 60s → ban
        ban_duration => 3600
    }
}.
```

Hot-reloadable. Change the config, call `reload/0`, rules update atomically
via netlink batch transactions. No connections dropped.

## Testing without root

The built-in kernel emulator (`nft_vm`) executes firewall rules in pure
userspace. Build synthetic packets, run them through your ruleset, verify
verdicts — all without CAP_NET_ADMIN, all in CI.

```erlang
Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,5}, dport => 22}),
{drop, _} = nft_vm:eval(Rules, Pkt).
```

129 tests run this way. Every rule path is verified before it touches the kernel.

## Architecture

```
erlkoenig_nft          Public API
    │
erlk_sup               rest_for_one supervisor
    │
    ├── nfnl_server     Shared netlink socket
    ├── erlk_nflog      NFLOG packet receiver
    ├── erlk_ct         Conntrack monitor (multicast)
    ├── erlk_ct_guard   Threat detection + auto-ban
    ├── erlk_watch_sup  Dynamic counter watchers
    └── erlk_firewall   Config owner, rule lifecycle
```

~10,000 lines of Erlang. 83 modules (45 hand-written, 38 generated).
IPv4 and IPv6 dual-stack throughout.

## Requirements

- Linux >= 5.0 (nf_tables)
- Erlang/OTP >= 27
- CAP_NET_ADMIN capability

## License

Apache-2.0
