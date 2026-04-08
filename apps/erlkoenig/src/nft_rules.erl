%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(nft_rules).
-moduledoc """
High-level rule builders for common firewall patterns.

Each function returns semantic expression terms (nft_expr_ir:rule())
that can be tested in the VM or encoded for the kernel:

    %% Test in VM
    Rule = nft_rules:tcp_accept(22),
    {accept, _} = nft_vm:eval_chain([Rule], Pkt),

    %% Send to kernel
    Msg = nft_encode:rule_fun(inet, T, C, Rule),
    nfnl_server:apply_msgs(Srv, [Msg]).

For functions that return multiple rules (tcp_accept_limited),
wrap each rule separately:

    Rules = nft_rules:tcp_accept_limited(22, <<"ssh">>, Opts),
    Msgs = [nft_encode:rule_fun(inet, T, C, R) || R <- Rules].
""".

-export([
    %% Rule builders (return terms)
    ct_established_accept/0,
    forward_established/0,
    iif_accept/0,
    iifname_accept/1,
    iifname_jump/2,
    iifname_oifname_jump/3,
    iifname_oifname_masq/2,
    oifname_accept/1,
    tcp_accept/1,
    tcp_accept_named/2,
    tcp_accept_limited/3,
    tcp_port_range_accept/2,
    tcp_reject/1,
    udp_accept/1,
    udp_accept_named/2,
    udp_accept_limited/3,
    udp_port_range_accept/2,
    icmp_accept/0,
    icmp_accept_named/1,
    icmpv6_accept/0,
    protocol_accept/1,
    ip_saddr_accept/1,
    ip_saddr_drop/1,
    set_lookup_drop/1,
    set_lookup_drop/2,
    set_lookup_drop_named/2,
    set_lookup_drop_named/3,
    set_lookup_accept/1,
    set_lookup_accept/2,
    set_lookup_accept_named/2,
    set_lookup_tcp_accept/1,
    connlimit_drop/2,
    log_drop/1,
    log_drop_named/2,
    log_drop_nflog/3,
    log_reject/1,
    masq_rule/0,
    oifname_neq_masq/1,
    dnat_rule/2,
    dnat_lb_rule/4,
    snat_rule/2,
    tcp_dnat/3,
    %% Per-source-IP rate limiting (meters)
    meter_limit/4,
    %% Cgroup matching (per-systemd-service rules)
    cgroup_accept/1,
    cgroup_drop/1,
    %% Conntrack mark
    ct_mark_set/1,
    ct_mark_match/2,
    %% Quota-based rules
    quota_accept/3,
    quota_drop/3,
    %% OS fingerprinting
    osf_match/2,
    %% Packet duplication (TEE/dup)
    dup_to/4,
    %% Set-based UDP accept (for SPA / WireGuard allowlisting)
    set_lookup_udp_accept/3,
    %% NFQUEUE (userspace packet processing)
    queue_rule/3,
    queue_range_rule/3,
    %% FIB reverse-path filtering
    fib_rpf_drop/0,
    %% NFLOG capture + drop (for SPA packet capture)
    nflog_capture_udp/3,
    %% SYN proxy (DDoS protection)
    synproxy_rules/2,
    synproxy_filter_rule/2,
    %% Conntrack bypass
    notrack_rule/2,
    %% Verdict map dispatch
    vmap_dispatch/2,
    concat_vmap_lookup/3,
    dnat_jhash_rule/4,
    %% Flow offload
    flow_offload/1,
    %% Concatenated set lookup
    concat_set_lookup/3,
    concat_set_lookup_drop/2,
    %% Set element operations (return msg_funs, not terms)
    ban_ip/3,
    ban_ip/4,
    unban_ip/3
]).

-export_type([rule/0]).

%% --- Types ---

-doc "A rule as a list of semantic expression terms.".
-type rule() :: nft_expr_ir:rule().

%% --- Constants ---

-define(INET, 1).
-define(REG1, 1).
-define(REG2, 2).
-define(TCP, 6).
-define(UDP, 17).
-define(ICMP, 1).
-define(ICMPV6, 58).

%% Conntrack state bits
-define(CT_ESTABLISHED, 16#02).
-define(CT_RELATED, 16#04).

%% ICMP types
-define(ICMP_ECHO_REQUEST, 8).
-define(ICMPV6_ECHO_REQUEST, 128).

-include("nft_constants.hrl").

%% --- Rule Builders (return semantic terms) ---

-doc """
Accept packets from established or related connections.

Should be the first rule in any chain with policy drop.
""".
-spec ct_established_accept() -> rule().
ct_established_accept() ->
    Mask = ?CT_ESTABLISHED bor ?CT_RELATED,
    [
        nft_expr_ir:ct(state, ?REG1),
        nft_expr_ir:bitwise(
            ?REG1,
            ?REG1,
            <<Mask:32/native>>,
            <<0:32>>
        ),
        nft_expr_ir:cmp(neq, ?REG1, <<0:32/native>>),
        nft_expr_ir:accept()
    ].

-doc """
Accept established/related in forward chain.

Same logic as ct_established_accept/0, use this in forward chains
for routers and NAT gateways.
""".
-spec forward_established() -> rule().
forward_established() ->
    ct_established_accept().

-doc "Accept all traffic on the loopback interface (ifindex 1).".
-spec iif_accept() -> rule().
iif_accept() ->
    [
        nft_expr_ir:meta(iif, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<1:32/native>>),
        nft_expr_ir:accept()
    ].

-doc "Accept all traffic on a named interface (e.g. <<\"br0\">>, <<\"wg0\">>).".
-spec iifname_accept(binary()) -> rule().
iifname_accept(Name) ->
    %% iifname is a 16-byte null-padded string
    Padded = pad_ifname(Name),
    [
        nft_expr_ir:meta(iifname, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, Padded),
        nft_expr_ir:accept()
    ].

-doc "Jump to a named chain if traffic arrives on the given interface.".
-spec iifname_jump(binary(), binary()) -> rule().
iifname_jump(Name, Target) ->
    Padded = pad_ifname(Name),
    [
        nft_expr_ir:meta(iifname, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, Padded),
        nft_expr_ir:jump(Target)
    ].

-doc "Jump to a named chain if traffic arrives on InIf and leaves via OutIf.".
-spec iifname_oifname_jump(binary(), binary(), binary()) -> rule().
iifname_oifname_jump(InIf, OutIf, Target) ->
    PaddedIn = pad_ifname(InIf),
    PaddedOut = pad_ifname(OutIf),
    [
        nft_expr_ir:meta(iifname, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, PaddedIn),
        nft_expr_ir:meta(oifname, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, PaddedOut),
        nft_expr_ir:jump(Target)
    ].

-doc "Masquerade traffic arriving on InIf and leaving via OutIf.".
-spec iifname_oifname_masq(binary(), binary()) -> rule().
iifname_oifname_masq(InIf, OutIf) ->
    PaddedIn = pad_ifname(InIf),
    PaddedOut = pad_ifname(OutIf),
    [
        nft_expr_ir:meta(iifname, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, PaddedIn),
        nft_expr_ir:meta(oifname, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, PaddedOut),
        nft_expr_ir:masq()
    ].

-doc "Accept traffic leaving via the given interface.".
-spec oifname_accept(binary()) -> rule().
oifname_accept(Name) ->
    Padded = pad_ifname(Name),
    [
        nft_expr_ir:meta(oifname, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, Padded),
        nft_expr_ir:accept()
    ].

-doc "Accept TCP traffic on the given port.".
-spec tcp_accept(0..65535) -> rule().
tcp_accept(Port) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
        nft_expr_ir:tcp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:accept()
    ].

-doc "Accept TCP traffic with a named counter.".
-spec tcp_accept_named(0..65535, binary()) -> rule().
tcp_accept_named(Port, CounterName) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
        nft_expr_ir:tcp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:objref_counter(CounterName),
        nft_expr_ir:accept()
    ].

-doc """
Rate-limited TCP accept. Returns TWO rules:
  1. tcp dport Port limit rate over Rate/s burst Burst drop
  2. tcp dport Port counter Name accept
""".
-spec tcp_accept_limited(0..65535, binary(), map()) -> [rule()].
tcp_accept_limited(Port, CounterName, #{rate := Rate, burst := Burst}) ->
    Match = [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
        nft_expr_ir:tcp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>)
    ],
    [
        Match ++
            [
                nft_expr_ir:limit_over(Rate, Burst),
                nft_expr_ir:drop()
            ],
        Match ++
            [
                nft_expr_ir:objref_counter(CounterName),
                nft_expr_ir:accept()
            ]
    ].

-doc "Accept TCP traffic on a port range (inclusive).".
-spec tcp_port_range_accept(0..65535, 0..65535) -> rule().
tcp_port_range_accept(From, To) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
        nft_expr_ir:tcp_dport(?REG1),
        nft_expr_ir:range(eq, ?REG1, <<From:16/big>>, <<To:16/big>>),
        nft_expr_ir:accept()
    ].

-doc "Reject TCP traffic on a port with TCP RST.".
-spec tcp_reject(0..65535) -> rule().
tcp_reject(Port) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
        nft_expr_ir:tcp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        %% type=1 = NFT_REJECT_TCP_RST, code ignored for TCP RST
        nft_expr_ir:reject(1, 0)
    ].

-doc "Accept UDP traffic on the given port.".
-spec udp_accept(0..65535) -> rule().
udp_accept(Port) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
        nft_expr_ir:udp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:accept()
    ].

-doc "Accept UDP traffic with a named counter.".
-spec udp_accept_named(0..65535, binary()) -> rule().
udp_accept_named(Port, CounterName) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
        nft_expr_ir:udp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:objref_counter(CounterName),
        nft_expr_ir:accept()
    ].

-doc """
Rate-limited UDP accept. Returns TWO rules:
  1. udp dport Port limit rate over Rate/s burst Burst drop
  2. udp dport Port counter Name accept
""".
-spec udp_accept_limited(0..65535, binary(), map()) -> [rule()].
udp_accept_limited(Port, CounterName, #{rate := Rate, burst := Burst}) ->
    Match = [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
        nft_expr_ir:udp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>)
    ],
    [
        Match ++
            [
                nft_expr_ir:limit_over(Rate, Burst),
                nft_expr_ir:drop()
            ],
        Match ++
            [
                nft_expr_ir:objref_counter(CounterName),
                nft_expr_ir:accept()
            ]
    ].

-doc "Accept UDP traffic on a port range (inclusive).".
-spec udp_port_range_accept(0..65535, 0..65535) -> rule().
udp_port_range_accept(From, To) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
        nft_expr_ir:udp_dport(?REG1),
        nft_expr_ir:range(eq, ?REG1, <<From:16/big>>, <<To:16/big>>),
        nft_expr_ir:accept()
    ].

-doc "Accept ICMP echo requests (ping).".
-spec icmp_accept() -> rule().
icmp_accept() ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?ICMP>>),
        nft_expr_ir:payload(transport, 0, 1, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?ICMP_ECHO_REQUEST>>),
        nft_expr_ir:accept()
    ].

-doc "Accept ICMP echo requests with a named counter.".
-spec icmp_accept_named(binary()) -> rule().
icmp_accept_named(CounterName) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?ICMP>>),
        nft_expr_ir:payload(transport, 0, 1, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?ICMP_ECHO_REQUEST>>),
        nft_expr_ir:objref_counter(CounterName),
        nft_expr_ir:accept()
    ].

-doc "Accept ICMPv6 echo requests (ping6). Required for IPv6 connectivity.".
-spec icmpv6_accept() -> rule().
icmpv6_accept() ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?ICMPV6>>),
        nft_expr_ir:payload(transport, 0, 1, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?ICMPV6_ECHO_REQUEST>>),
        nft_expr_ir:accept()
    ].

-doc "Accept all traffic of the given protocol.".
-spec protocol_accept(icmp | icmpv6 | tcp | udp | 0..255) -> [nft_expr_ir:expr(), ...].
protocol_accept(Proto) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<(proto_num(Proto))>>),
        nft_expr_ir:accept()
    ].

-doc "Accept traffic from a specific source address (4 or 16 byte binary).".
-spec ip_saddr_accept(binary()) -> rule().
ip_saddr_accept(IP) when byte_size(IP) =:= 4 ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
        nft_expr_ir:ip_saddr(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, IP),
        nft_expr_ir:accept()
    ];
ip_saddr_accept(IP) when byte_size(IP) =:= 16 ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
        nft_expr_ir:ip6_saddr(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, IP),
        nft_expr_ir:accept()
    ].

-doc "Drop traffic from a specific source address (4 or 16 byte binary).".
-spec ip_saddr_drop(binary()) -> rule().
ip_saddr_drop(IP) when byte_size(IP) =:= 4 ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
        nft_expr_ir:ip_saddr(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, IP),
        nft_expr_ir:drop()
    ];
ip_saddr_drop(IP) when byte_size(IP) =:= 16 ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
        nft_expr_ir:ip6_saddr(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, IP),
        nft_expr_ir:drop()
    ].

-doc "Drop if source IP is in the named set (IPv4).".
-spec set_lookup_drop(binary()) -> rule().
set_lookup_drop(SetName) ->
    set_lookup_drop(SetName, ipv4_addr).

-doc "Drop if source IP is in the named set with explicit address type.".
-spec set_lookup_drop(binary(), ipv4_addr | ipv6_addr) -> rule().
set_lookup_drop(SetName, ipv4_addr) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
        nft_expr_ir:ip_saddr(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:drop()
    ];
set_lookup_drop(SetName, ipv6_addr) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
        nft_expr_ir:ip6_saddr(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:drop()
    ].

-doc "Drop from set with a named counter (IPv4).".
-spec set_lookup_drop_named(binary(), binary()) -> rule().
set_lookup_drop_named(SetName, CounterName) ->
    set_lookup_drop_named(SetName, CounterName, ipv4_addr).

-doc "Drop from set with a named counter and explicit address type.".
-spec set_lookup_drop_named(binary(), binary(), ipv4_addr | ipv6_addr) -> rule().
set_lookup_drop_named(SetName, CounterName, ipv4_addr) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
        nft_expr_ir:ip_saddr(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:objref_counter(CounterName),
        nft_expr_ir:drop()
    ];
set_lookup_drop_named(SetName, CounterName, ipv6_addr) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
        nft_expr_ir:ip6_saddr(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:objref_counter(CounterName),
        nft_expr_ir:drop()
    ].

-doc "Accept if source IP is in the named set (IPv4).".
-spec set_lookup_accept(binary()) -> rule().
set_lookup_accept(SetName) ->
    set_lookup_accept(SetName, ipv4_addr).

-doc "Accept if source IP is in the named set with explicit address type.".
-spec set_lookup_accept(binary(), ipv4_addr | ipv6_addr) -> rule().
set_lookup_accept(SetName, ipv4_addr) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
        nft_expr_ir:ip_saddr(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:accept()
    ];
set_lookup_accept(SetName, ipv6_addr) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
        nft_expr_ir:ip6_saddr(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:accept()
    ].

-doc "Accept if source IP is in the named set, with a named counter.".
-spec set_lookup_accept_named(binary(), binary()) -> rule().
set_lookup_accept_named(SetName, CounterName) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
        nft_expr_ir:ip_saddr(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:objref_counter(CounterName),
        nft_expr_ir:accept()
    ].

-doc "Accept if TCP destination port is in the named set (inet_service).".
-spec set_lookup_tcp_accept(binary()) -> rule().
set_lookup_tcp_accept(SetName) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<6>>),
        nft_expr_ir:tcp_dport(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:accept()
    ].

-doc "Drop when concurrent connections exceed Count. Flags: 0=over, 1=invert.".
-spec connlimit_drop(non_neg_integer(), non_neg_integer()) -> rule().
connlimit_drop(Count, Flags) ->
    [
        nft_expr_ir:connlimit(Count, Flags),
        nft_expr_ir:drop()
    ].

-doc """
Per-source-IP rate limit using dynamic set (meter).

Creates a rule that matches a protocol/port, then uses a dynamic set
(meter) keyed by source IP to rate-limit each source independently.
Packets exceeding the per-IP rate are dropped.

Options:
    rate  — packets per unit (required)
    burst — token bucket depth (default 5)
    unit  — second | minute | hour | day (default second)
""".
-spec meter_limit(binary(), 0..65535, tcp | udp, map()) -> rule().
meter_limit(SetName, Port, Proto, Opts) ->
    Rate = maps:get(rate, Opts),
    Burst = maps:get(burst, Opts, 5),
    Unit = maps:get(unit, Opts, second),
    ProtoNum = proto_num(Proto),
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<ProtoNum>>),
        case Proto of
            tcp -> nft_expr_ir:tcp_dport(?REG1);
            udp -> nft_expr_ir:udp_dport(?REG1)
        end,
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:ip_saddr(?REG1),
        nft_expr_ir:meter(SetName, ?REG1, Rate, Burst, Unit),
        nft_expr_ir:drop()
    ].

-doc "Log and drop all unmatched traffic.".
-spec log_drop(binary()) -> rule().
log_drop(Prefix) ->
    [
        nft_expr_ir:log(#{prefix => Prefix}),
        nft_expr_ir:drop()
    ].

-doc "Log and drop with a named counter.".
-spec log_drop_named(binary(), binary()) -> rule().
log_drop_named(Prefix, CounterName) ->
    [
        nft_expr_ir:log(#{prefix => Prefix}),
        nft_expr_ir:objref_counter(CounterName),
        nft_expr_ir:drop()
    ].

-doc "Log to NFLOG group, count, and drop.".
-spec log_drop_nflog(binary(), non_neg_integer(), binary()) -> rule().
log_drop_nflog(Prefix, Group, CounterName) ->
    [
        nft_expr_ir:log(#{prefix => Prefix, group => Group}),
        nft_expr_ir:objref_counter(CounterName),
        nft_expr_ir:drop()
    ].

-doc "Log and reject with ICMP unreachable (instead of silent drop).".
-spec log_reject(binary()) -> rule().
log_reject(Prefix) ->
    [
        nft_expr_ir:log(#{prefix => Prefix}),
        nft_expr_ir:reject()
    ].

-doc "Masquerade outgoing traffic (dynamic SNAT for NAT gateways).".
-spec masq_rule() -> rule().
masq_rule() ->
    [nft_expr_ir:masq()].

-doc "Masquerade traffic leaving via any interface except the named one.".
-spec oifname_neq_masq(binary()) -> rule().
oifname_neq_masq(IfName) ->
    Padded = pad_ifname(IfName),
    [
        nft_expr_ir:meta(oifname, ?REG1),
        nft_expr_ir:cmp(neq, ?REG1, Padded),
        nft_expr_ir:masq()
    ].

-doc """
DNAT with source-IP hash loadbalancing (jhash).

For 1 target: degenerates to simple DNAT (no hash).
For N targets: jhash(ip saddr) mod N → lookup data map → DNAT.
Same source IP always maps to the same backend (sticky sessions).

Expression chain:
  1. payload: load ip saddr into REG1 (4 bytes)
  2. hash: jhash(REG1, len=4, mod=N) → REG1 (result: 0..N-1)
  3. lookup: REG1 in named data map → REG1 (result: container IP)
  4. immediate: load port into REG2
  5. dnat: REG1 (IP) + REG2 (port)

The named data map must be created separately before this rule
(nft_set:add_data_map + nft_set_elem:add_data_map_elems).
""".
-spec dnat_lb_rule([binary()], 0..65535, binary(), non_neg_integer()) -> rule().
dnat_lb_rule([SingleIp], Port, _MapName, _MapId) ->
    %% Degenerate case: 1 target = simple DNAT
    dnat_rule(SingleIp, Port);
dnat_lb_rule(Targets, Port, MapName, MapId) when length(Targets) > 1 ->
    N = length(Targets),
    [
        %% 1. Match IPv4 only (meta nfproto == ipv4).
        %%    Without this, nft renders the payload as @nh,96,32 instead of ip saddr.
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<2>>),  %% AF_INET = 2
        %% 2. Load source IP into REG2 (REG1 is used by meta/cmp)
        nft_expr_ir:ip_saddr(?REG2),
        %% 3. Jenkins hash mod N → REG1 (0..N-1)
        nft_expr_ir:hash(?REG2, 4, N, ?REG1),
        %% 4. Lookup hash result in named data map → REG1 (container IP)
        nft_expr_ir:lookup_data(?REG1, MapName, ?REG1, MapId),
        %% 5. Load port into REG2
        nft_expr_ir:immediate_data(?REG2, <<Port:16/big>>),
        %% 6. DNAT to REG1:REG2 (IP:Port)
        nft_expr_ir:dnat(?REG1, ?REG2, 2)
    ].

-spec dnat_rule(binary(), 0..65535) -> rule().
dnat_rule(IP, Port) when byte_size(IP) =:= 4; byte_size(IP) =:= 16 ->
    Family = ip_family(IP),
    [
        nft_expr_ir:immediate_data(?REG1, IP),
        nft_expr_ir:immediate_data(?REG2, <<Port:16/big>>),
        nft_expr_ir:dnat(?REG1, ?REG2, Family)
    ].

-doc "SNAT: rewrite source address (and optionally port).".
-spec snat_rule(binary(), 0..65535) -> rule().
snat_rule(IP, 0) when byte_size(IP) =:= 4; byte_size(IP) =:= 16 ->
    %% Port 0 = address-only SNAT (no port rewrite)
    Family = ip_family(IP),
    [
        nft_expr_ir:immediate_data(?REG1, IP),
        nft_expr_ir:snat_addr(?REG1, Family)
    ];
snat_rule(IP, Port) when byte_size(IP) =:= 4; byte_size(IP) =:= 16 ->
    Family = ip_family(IP),
    [
        nft_expr_ir:immediate_data(?REG1, IP),
        nft_expr_ir:immediate_data(?REG2, <<Port:16/big>>),
        nft_expr_ir:snat(?REG1, ?REG2, Family)
    ].

-doc "DNAT TCP traffic on MatchPort to DstIp:DstPort.".
-spec tcp_dnat(0..65535, binary(), 0..65535) -> rule().
tcp_dnat(MatchPort, DstIp, DstPort) when
    byte_size(DstIp) =:= 4; byte_size(DstIp) =:= 16
->
    Family = ip_family(DstIp),
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
        nft_expr_ir:tcp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<MatchPort:16/big>>),
        nft_expr_ir:immediate_data(?REG1, DstIp),
        nft_expr_ir:immediate_data(?REG2, <<DstPort:16/big>>),
        nft_expr_ir:dnat(?REG1, ?REG2, Family)
    ].

-doc """
Accept traffic on port+proto while under a byte quota.

Mode: until (flags=0) — quota matches while under the limit.
The quota expression is an anonymous inline quota (not a named objref).
""".
-spec quota_accept(0..65535, tcp | udp, map()) -> rule().
quota_accept(Port, Proto, #{bytes := Bytes, mode := Mode}) ->
    Flags = quota_flags(Mode),
    ProtoNum = proto_num(Proto),
    DportFun =
        case Proto of
            tcp -> fun nft_expr_ir:tcp_dport/1;
            udp -> fun nft_expr_ir:udp_dport/1
        end,
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<ProtoNum>>),
        DportFun(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:quota(Bytes, Flags),
        nft_expr_ir:accept()
    ].

-doc """
Drop traffic on port+proto when over a byte quota.

Mode: over (flags=1) — quota matches when the limit is exceeded.
""".
-spec quota_drop(0..65535, tcp | udp, map()) -> rule().
quota_drop(Port, Proto, #{bytes := Bytes, mode := Mode}) ->
    Flags = quota_flags(Mode),
    ProtoNum = proto_num(Proto),
    DportFun =
        case Proto of
            tcp -> fun nft_expr_ir:tcp_dport/1;
            udp -> fun nft_expr_ir:udp_dport/1
        end,
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<ProtoNum>>),
        DportFun(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:quota(Bytes, Flags),
        nft_expr_ir:drop()
    ].

-doc """
Duplicate (TEE) matching packets to another address via a device.

Matches traffic on Port/Proto, then duplicates the packet to Addr
via the output device with ifindex Device. The original packet
continues through the chain — dup is a side-effect, not a terminal.

Addr is a 4-byte (IPv4) or 16-byte (IPv6) binary.
Device is the output interface index (integer).
Port is the destination port to match.
Proto is tcp or udp.

Example:
    %% Mirror all TCP/443 traffic to 10.0.0.2 via eth1 (ifindex 3)
    Rule = nft_rules:dup_to(<<10,0,0,2>>, 3, 443, tcp),
""".
-spec dup_to(binary(), non_neg_integer(), 0..65535, tcp | udp) -> rule().
dup_to(Addr, Device, Port, tcp) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
        nft_expr_ir:tcp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:immediate_data(?REG1, Addr),
        nft_expr_ir:immediate_data(?REG2, <<Device:32/native>>),
        nft_expr_ir:dup(?REG1, ?REG2)
    ];
dup_to(Addr, Device, Port, udp) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
        nft_expr_ir:udp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:immediate_data(?REG1, Addr),
        nft_expr_ir:immediate_data(?REG2, <<Device:32/native>>),
        nft_expr_ir:dup(?REG1, ?REG2)
    ].

-doc """
Accept UDP traffic on a port if source IP is in the named set.

Used for WireGuard SPA: only allow UDP 51820 if the client's IP
has been authorized via SPA and added to the allowlist set.
""".
-spec set_lookup_udp_accept(binary(), 0..65535, ipv4_addr | ipv6_addr) -> rule().
set_lookup_udp_accept(SetName, Port, ipv4_addr) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
        nft_expr_ir:meta(l4proto, ?REG2),
        nft_expr_ir:cmp(eq, ?REG2, <<?UDP>>),
        nft_expr_ir:udp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:ip_saddr(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:accept()
    ];
set_lookup_udp_accept(SetName, Port, ipv6_addr) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
        nft_expr_ir:meta(l4proto, ?REG2),
        nft_expr_ir:cmp(eq, ?REG2, <<?UDP>>),
        nft_expr_ir:udp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:ip6_saddr(?REG1),
        nft_expr_ir:lookup(?REG1, SetName),
        nft_expr_ir:accept()
    ].

-doc """
Capture a UDP packet on a port via NFLOG and drop it.

Used for SPA: the UDP packet on the SPA port is logged to an NFLOG
group for userspace processing, then dropped so it never reaches
the target service.
""".
-spec nflog_capture_udp(0..65535, binary(), non_neg_integer()) -> rule().
nflog_capture_udp(Port, Prefix, Group) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
        nft_expr_ir:udp_dport(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:log(#{prefix => Prefix, group => Group, snaplen => 128}),
        nft_expr_ir:drop()
    ].

-doc "Skip conntrack for port/proto. Use in raw prerouting chain (priority -300).".
-spec notrack_rule(0..65535, atom() | 0..255) -> rule().
notrack_rule(Port, Proto) ->
    ProtoNum = proto_num(Proto),
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<ProtoNum>>),
        case Proto of
            tcp -> nft_expr_ir:tcp_dport(?REG1);
            udp -> nft_expr_ir:udp_dport(?REG1)
        end,
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:notrack()
    ].

%% --- SYN Proxy Rule Builders ---

-doc """
Build a complete set of synproxy rules for the given ports.

Returns a 2-tuple: {NotrackRules, FilterRules}.
- NotrackRules go into a raw prerouting chain (priority -300, policy accept)
- FilterRules go into the input filter chain

Each port gets one notrack rule and one synproxy filter rule.
""".
-spec synproxy_rules([0..65535], map()) -> {[rule()], [rule()]}.
synproxy_rules(Ports, Opts) when is_list(Ports), is_map(Opts) ->
    NotrackRules = [notrack_rule(P, tcp) || P <- Ports],
    FilterRules = [synproxy_filter_rule(P, Opts) || P <- Ports],
    {NotrackRules, FilterRules}.

-doc """
Build a synproxy filter rule for a single TCP port.

Matches ct state invalid|untracked + TCP dport, then applies synproxy.
Use with a corresponding notrack_rule/2 in the raw chain.
""".
-spec synproxy_filter_rule(0..65535, #{
    mss := non_neg_integer(), wscale := non_neg_integer(), _ => _
}) -> [nft_expr_ir:expr(), ...].
synproxy_filter_rule(Port, Opts) ->
    nft_expr_ir:synproxy_filter_rule(Port, Opts).

%% --- NFQUEUE Rule Builders ---

-doc "Queue matching packets to userspace NFQUEUE.".
-spec queue_rule(0..65535, tcp | udp, map()) -> rule().
queue_rule(Port, Proto, Opts) ->
    ProtoNum = proto_num(Proto),
    Num = maps:get(num, Opts),
    QueueFlags = maps:get(flags, Opts, []),
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<ProtoNum>>),
        case Proto of
            tcp -> nft_expr_ir:tcp_dport(?REG1);
            udp -> nft_expr_ir:udp_dport(?REG1)
        end,
        nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
        nft_expr_ir:queue(Num, #{flags => QueueFlags})
    ].

-doc "Queue matching packets in a port range to userspace NFQUEUE.".
-spec queue_range_rule({0..65535, 0..65535}, tcp | udp, map()) -> rule().
queue_range_rule({FromPort, ToPort}, Proto, Opts) ->
    ProtoNum = proto_num(Proto),
    QueueNum = maps:get(num, Opts),
    QueueFlags = maps:get(flags, Opts, []),
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<ProtoNum>>),
        case Proto of
            tcp -> nft_expr_ir:tcp_dport(?REG1);
            udp -> nft_expr_ir:udp_dport(?REG1)
        end,
        nft_expr_ir:range(eq, ?REG1, <<FromPort:16/big>>, <<ToPort:16/big>>),
        nft_expr_ir:queue(QueueNum, #{flags => QueueFlags})
    ].

%% --- Cgroup Matching (per-systemd-service rules) ---

-doc "Accept packets from sockets in the given cgroupv2 ID.".
-spec cgroup_accept(non_neg_integer()) -> rule().
cgroup_accept(CgroupId) ->
    [
        nft_expr_ir:socket_cgroup(2),
        nft_expr_ir:cmp(eq, ?REG1, <<CgroupId:64/native>>),
        nft_expr_ir:accept()
    ].

-doc "Drop packets from sockets in the given cgroupv2 ID.".
-spec cgroup_drop(non_neg_integer()) -> rule().
cgroup_drop(CgroupId) ->
    [
        nft_expr_ir:socket_cgroup(2),
        nft_expr_ir:cmp(eq, ?REG1, <<CgroupId:64/native>>),
        nft_expr_ir:drop()
    ].
-doc """
Dispatch TCP traffic to chains via a verdict map.

Takes a vmap set name and builds a rule that loads the TCP
destination port into reg1 and performs a verdict map lookup.

The vmap set and its elements (port -> chain verdict mappings)
must be created separately via nft_set:add_vmap/4 and
nft_set_elem:add_vmap_elems/5.

Example:
    Rule = nft_rules:vmap_dispatch(tcp, <<"port_dispatch">>),
    %% Equivalent to: tcp dport vmap @port_dispatch
""".
-spec vmap_dispatch(tcp | udp, binary()) -> rule().
vmap_dispatch(tcp, VmapName) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
        nft_expr_ir:tcp_dport(?REG1),
        nft_expr_ir:vmap_lookup(?REG1, VmapName)
    ];
vmap_dispatch(udp, VmapName) ->
    [
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
        nft_expr_ir:udp_dport(?REG1),
        nft_expr_ir:vmap_lookup(?REG1, VmapName)
    ].

-doc """
jhash DNAT rule using an explicit named data map.

The map must be created separately via nft_map in the DSL.
Mod is the jhash modulus (number of map entries).
""".
-spec dnat_jhash_rule(pos_integer(), 0..65535, binary(), non_neg_integer()) -> rule().
dnat_jhash_rule(Mod, Port, MapName, MapId) ->
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<2>>),
        nft_expr_ir:ip_saddr(?REG2),
        nft_expr_ir:hash(?REG2, 4, Mod, ?REG1),
        nft_expr_ir:lookup_data(?REG1, MapName, ?REG1, MapId),
        nft_expr_ir:immediate_data(?REG2, <<Port:16/big>>),
        nft_expr_ir:dnat(?REG1, ?REG2, 2)
    ].

-doc """
Concatenated verdict map lookup: ip saddr . ip daddr . tcp dport vmap @name.

Loads source IP into REG1, destination IP into REG2, TCP destination port
into REG3, then performs a concatenated verdict map lookup. The kernel
matches all three fields as one composite key in O(1).
""".
-spec concat_vmap_lookup(binary(), [atom()], non_neg_integer()) -> rule().
concat_vmap_lookup(VmapName, [ip_saddr, ip_daddr, tcp_dport], SetId) ->
    %% Concat lookups require consecutive 32-bit registers (NFT_REG32_xx).
    %% Old 128-bit registers (REG_1=1..REG_4=4) are too wide.
    %% NFT_REG32_00 = 8, NFT_REG32_01 = 9, etc.
    R32_0 = 8,   %% NFT_REG32_00
    R32_1 = 9,   %% NFT_REG32_01
    R32_2 = 10,  %% NFT_REG32_02
    [
        nft_expr_ir:meta(nfproto, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<2>>),     %% AF_INET
        nft_expr_ir:ip_saddr(R32_0),            %% REG32_00 = saddr (4 bytes)
        nft_expr_ir:ip_daddr(R32_1),            %% REG32_01 = daddr (4 bytes)
        nft_expr_ir:tcp_dport(R32_2),           %% REG32_02 = dport (2 bytes)
        %% Concat lookup: reads 12 bytes starting at REG32_00
        {lookup, #{sreg => R32_0, set => VmapName, dreg => 0, set_id => SetId}}
    ].
-doc """
Offload established connections to a named flowtable.

Used in forward chains to fast-path established flows, bypassing
the full nf_tables evaluation pipeline for improved throughput.

Example:
    Rule = nft_rules:flow_offload(<<"ft0">>).
""".
-spec flow_offload(binary()) -> rule().
flow_offload(FlowtableName) ->
    nft_expr_ir:flow_offload(FlowtableName).
%% --- Conntrack Mark ---

-doc """
Set the conntrack mark on the current connection.

Loads the mark value into a register and writes it to the conntrack entry.
Use this to tag connections in one chain and match them in another.
""".
-spec ct_mark_set(non_neg_integer()) -> rule().
ct_mark_set(Value) ->
    [
        nft_expr_ir:immediate_data(?REG1, <<Value:32/native>>),
        nft_expr_ir:ct_mark_set(?REG1)
    ].

-doc """
Match packets whose conntrack mark equals Value, then apply Verdict.

Loads the ct mark into a register and compares it against Value.
Verdict is typically accept() or drop().
""".
-spec ct_mark_match(non_neg_integer(), nft_expr_ir:expr()) -> rule().
ct_mark_match(Value, accept) ->
    [
        nft_expr_ir:ct_mark(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Value:32/native>>),
        nft_expr_ir:accept()
    ];
ct_mark_match(Value, drop) ->
    [
        nft_expr_ir:ct_mark(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Value:32/native>>),
        nft_expr_ir:drop()
    ];
ct_mark_match(Value, Verdict) ->
    [
        nft_expr_ir:ct_mark(?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<Value:32/native>>),
        Verdict
    ].
-doc """
Drop packets that fail reverse-path filtering (BCP38 / anti-spoofing).

Uses FIB lookup: if source address has no route back via the input
interface (oif == 0), the source is spoofed and the packet is dropped.

Equivalent to nftables: `fib saddr . iif oif eq 0 drop`
""".
-spec fib_rpf_drop() -> rule().
fib_rpf_drop() ->
    nft_expr_ir:fib_rpf().
-doc """
Match OS fingerprint and apply verdict.

Uses passive TCP SYN fingerprinting to identify the OS, then
compares with the given name (e.g. <<"Linux">>, <<"Windows">>).
""".
-spec osf_match(binary(), accept | drop) -> rule().
osf_match(OsName, Verdict) ->
    nft_expr_ir:osf_match(?REG1, OsName) ++ [verdict_expr(Verdict)].
%% --- Concatenated Set Lookup ---

-doc """
Accept if the concatenated key matches an entry in the named set.

Fields is a list of symbolic field names (ip_saddr, tcp_dport, etc.)
that are loaded into consecutive registers and looked up as a single
composite key.

Example:
    %% ip saddr . tcp dport { 10.0.0.1 . 22 }
    concat_set_lookup(<<"allowpairs">>, [ip_saddr, tcp_dport], accept)
""".
-spec concat_set_lookup(
    binary(),
    [
        ip_saddr
        | ip_daddr
        | ip6_saddr
        | ip6_daddr
        | tcp_sport
        | tcp_dport
        | udp_sport
        | udp_dport
        | ip_protocol
    ],
    accept | drop
) -> [nft_expr_ir:expr(), ...].
concat_set_lookup(SetName, Fields, Verdict) ->
    KeyExprs = [field_to_expr(F) || F <- Fields],
    nft_expr_ir:concat_lookup(SetName, KeyExprs, Verdict).

-doc """
Drop if the concatenated key matches an entry in the named set.

Example:
    concat_set_lookup_drop(<<"denylist">>, [ip_saddr, tcp_dport])
""".
-spec concat_set_lookup_drop(binary(), [
    ip_saddr
    | ip_daddr
    | ip6_saddr
    | ip6_daddr
    | tcp_sport
    | tcp_dport
    | udp_sport
    | udp_dport
    | ip_protocol
]) -> [nft_expr_ir:expr(), ...].
concat_set_lookup_drop(SetName, Fields) ->
    concat_set_lookup(SetName, Fields, drop).

%% Map symbolic field names to {IR_expression, byte_length} tuples.
-spec field_to_expr(
    ip_saddr
    | ip_daddr
    | ip6_saddr
    | ip6_daddr
    | tcp_sport
    | tcp_dport
    | udp_sport
    | udp_dport
    | ip_protocol
) ->
    {
        {payload, #{
            base := atom(),
            dreg := non_neg_integer(),
            len := pos_integer(),
            offset := non_neg_integer()
        }},
        1 | 2 | 4 | 16
    }.
field_to_expr(ip_saddr) -> {nft_expr_ir:ip_saddr(?REG1), 4};
field_to_expr(ip_daddr) -> {nft_expr_ir:ip_daddr(?REG1), 4};
field_to_expr(ip6_saddr) -> {nft_expr_ir:ip6_saddr(?REG1), 16};
field_to_expr(ip6_daddr) -> {nft_expr_ir:ip6_daddr(?REG1), 16};
field_to_expr(tcp_sport) -> {nft_expr_ir:tcp_sport(?REG1), 2};
field_to_expr(tcp_dport) -> {nft_expr_ir:tcp_dport(?REG1), 2};
field_to_expr(udp_sport) -> {nft_expr_ir:udp_sport(?REG1), 2};
field_to_expr(udp_dport) -> {nft_expr_ir:udp_dport(?REG1), 2};
field_to_expr(ip_protocol) -> {nft_expr_ir:ip_protocol(?REG1), 1}.

%% --- Set Element Operations (msg_funs, not terms) ---

-doc "Add an IP address to a named set (ban).".
-spec ban_ip(binary(), binary(), binary()) -> fun((non_neg_integer()) -> binary()).
ban_ip(Table, SetName, IP) when byte_size(IP) =:= 4; byte_size(IP) =:= 16 ->
    fun(Seq) ->
        nft_set_elem:add(?INET, Table, SetName, IP, Seq)
    end.

-doc "Add an IP address to a named set with kernel-side timeout (milliseconds).".
-spec ban_ip(binary(), binary(), binary(), non_neg_integer()) ->
    fun((non_neg_integer()) -> binary()).
ban_ip(Table, SetName, IP, TimeoutMs) when byte_size(IP) =:= 4; byte_size(IP) =:= 16 ->
    fun(Seq) ->
        nft_set_elem:add(?INET, Table, SetName, IP, TimeoutMs, Seq)
    end.

-doc "Remove an IP address from a named set (unban).".
-spec unban_ip(binary(), binary(), binary()) -> fun((non_neg_integer()) -> binary()).
unban_ip(Table, SetName, IP) when byte_size(IP) =:= 4; byte_size(IP) =:= 16 ->
    fun(Seq) ->
        nft_set_elem:del(?INET, Table, SetName, IP, Seq)
    end.

%% --- Internal ---

-spec verdict_expr(accept | drop) -> nft_expr_ir:expr().
verdict_expr(accept) -> nft_expr_ir:accept();
verdict_expr(drop) -> nft_expr_ir:drop().

-spec proto_num(icmp | icmpv6 | tcp | udp | 0..255) -> 0..255.
proto_num(icmp) -> 1;
proto_num(tcp) -> 6;
proto_num(udp) -> 17;
proto_num(icmpv6) -> 58;
proto_num(N) when is_integer(N), N >= 0, N =< 255 -> N.

-spec pad_ifname(binary()) -> binary().
pad_ifname(Name) when byte_size(Name) =< 16 ->
    Pad = 16 - byte_size(Name),
    <<Name/binary, 0:(Pad * 8)>>.

%% NFPROTO_IPV4 = 2, NFPROTO_IPV6 = 10
ip_family(IP) when byte_size(IP) =:= 4 -> 2;
ip_family(IP) when byte_size(IP) =:= 16 -> 10.

-spec quota_flags(until | over) -> 0 | 1.
quota_flags(until) -> 0;
quota_flags(over) -> 1.
