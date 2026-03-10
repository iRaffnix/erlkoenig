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
    icmpv6_accept/0,
    protocol_accept/1,
    ip_saddr_accept/1,
    ip_saddr_drop/1,
    set_lookup_drop/1,
    set_lookup_drop/2,
    set_lookup_drop_named/2,
    set_lookup_drop_named/3,
    connlimit_drop/2,
    log_drop/1,
    log_drop_named/2,
    log_drop_nflog/3,
    log_reject/1,
    masq_rule/0,
    oifname_neq_masq/1,
    dnat_rule/2,
    tcp_dnat/3,
    %% Set-based UDP accept (for SPA / WireGuard allowlisting)
    set_lookup_udp_accept/3,
    %% NFLOG capture + drop (for SPA packet capture)
    nflog_capture_udp/3,
    %% Set element operations (return msg_funs, not terms)
    ban_ip/3,
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
-define(TCP,  6).
-define(UDP, 17).
-define(ICMP, 1).
-define(ICMPV6, 58).

%% Conntrack state bits
-define(CT_ESTABLISHED, 16#02).
-define(CT_RELATED,     16#04).

%% ICMP types
-define(ICMP_ECHO_REQUEST, 8).
-define(ICMPV6_ECHO_REQUEST, 128).

%% Address family values
-define(NFPROTO_IPV4, 2).
-define(NFPROTO_IPV6, 10).

%% --- Rule Builders (return semantic terms) ---

-doc """
Accept packets from established or related connections.

Should be the first rule in any chain with policy drop.
""".
-spec ct_established_accept() -> rule().
ct_established_accept() ->
    Mask = ?CT_ESTABLISHED bor ?CT_RELATED,
    [nft_expr_ir:ct(state, ?REG1),
     nft_expr_ir:bitwise(?REG1, ?REG1,
         <<Mask:32/native>>, <<0:32>>),
     nft_expr_ir:cmp(neq, ?REG1, <<0:32/native>>),
     nft_expr_ir:accept()].

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
    [nft_expr_ir:meta(iif, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<1:32/native>>),
     nft_expr_ir:accept()].

-doc "Accept all traffic on a named interface (e.g. <<\"br0\">>, <<\"wg0\">>).".
-spec iifname_accept(binary()) -> rule().
iifname_accept(Name) ->
    %% iifname is a 16-byte null-padded string
    Padded = pad_ifname(Name),
    [nft_expr_ir:meta(iifname, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, Padded),
     nft_expr_ir:accept()].

-doc "Jump to a named chain if traffic arrives on the given interface.".
-spec iifname_jump(binary(), binary()) -> rule().
iifname_jump(Name, Target) ->
    Padded = pad_ifname(Name),
    [nft_expr_ir:meta(iifname, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, Padded),
     nft_expr_ir:jump(Target)].

-doc "Accept traffic leaving via the given interface.".
-spec oifname_accept(binary()) -> rule().
oifname_accept(Name) ->
    Padded = pad_ifname(Name),
    [nft_expr_ir:meta(oifname, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, Padded),
     nft_expr_ir:accept()].

-doc "Accept TCP traffic on the given port.".
-spec tcp_accept(0..65535) -> rule().
tcp_accept(Port) ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
     nft_expr_ir:tcp_dport(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
     nft_expr_ir:accept()].

-doc "Accept TCP traffic with a named counter.".
-spec tcp_accept_named(0..65535, binary()) -> rule().
tcp_accept_named(Port, CounterName) ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
     nft_expr_ir:tcp_dport(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
     nft_expr_ir:objref_counter(CounterName),
     nft_expr_ir:accept()].

-doc """
Rate-limited TCP accept. Returns TWO rules:
  1. tcp dport Port limit rate over Rate/s burst Burst drop
  2. tcp dport Port counter Name accept
""".
-spec tcp_accept_limited(0..65535, binary(), map()) -> [rule()].
tcp_accept_limited(Port, CounterName, #{rate := Rate, burst := Burst}) ->
    Match = [nft_expr_ir:meta(l4proto, ?REG1),
             nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
             nft_expr_ir:tcp_dport(?REG1),
             nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>)],
    [Match ++ [nft_expr_ir:limit_over(Rate, Burst),
               nft_expr_ir:drop()],
     Match ++ [nft_expr_ir:objref_counter(CounterName),
               nft_expr_ir:accept()]].

-doc "Accept TCP traffic on a port range (inclusive).".
-spec tcp_port_range_accept(0..65535, 0..65535) -> rule().
tcp_port_range_accept(From, To) ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
     nft_expr_ir:tcp_dport(?REG1),
     nft_expr_ir:range(eq, ?REG1, <<From:16/big>>, <<To:16/big>>),
     nft_expr_ir:accept()].

-doc "Reject TCP traffic on a port with TCP RST.".
-spec tcp_reject(0..65535) -> rule().
tcp_reject(Port) ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
     nft_expr_ir:tcp_dport(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
     nft_expr_ir:reject(2, 0)].  %% type=2 (tcp reset), code ignored

-doc "Accept UDP traffic on the given port.".
-spec udp_accept(0..65535) -> rule().
udp_accept(Port) ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
     nft_expr_ir:udp_dport(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
     nft_expr_ir:accept()].

-doc "Accept UDP traffic with a named counter.".
-spec udp_accept_named(0..65535, binary()) -> rule().
udp_accept_named(Port, CounterName) ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
     nft_expr_ir:udp_dport(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
     nft_expr_ir:objref_counter(CounterName),
     nft_expr_ir:accept()].

-doc """
Rate-limited UDP accept. Returns TWO rules:
  1. udp dport Port limit rate over Rate/s burst Burst drop
  2. udp dport Port counter Name accept
""".
-spec udp_accept_limited(0..65535, binary(), map()) -> [rule()].
udp_accept_limited(Port, CounterName, #{rate := Rate, burst := Burst}) ->
    Match = [nft_expr_ir:meta(l4proto, ?REG1),
             nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
             nft_expr_ir:udp_dport(?REG1),
             nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>)],
    [Match ++ [nft_expr_ir:limit_over(Rate, Burst),
               nft_expr_ir:drop()],
     Match ++ [nft_expr_ir:objref_counter(CounterName),
               nft_expr_ir:accept()]].

-doc "Accept UDP traffic on a port range (inclusive).".
-spec udp_port_range_accept(0..65535, 0..65535) -> rule().
udp_port_range_accept(From, To) ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
     nft_expr_ir:udp_dport(?REG1),
     nft_expr_ir:range(eq, ?REG1, <<From:16/big>>, <<To:16/big>>),
     nft_expr_ir:accept()].

-doc "Accept ICMP echo requests (ping).".
-spec icmp_accept() -> rule().
icmp_accept() ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?ICMP>>),
     nft_expr_ir:payload(transport, 0, 1, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?ICMP_ECHO_REQUEST>>),
     nft_expr_ir:accept()].

-doc "Accept ICMPv6 echo requests (ping6). Required for IPv6 connectivity.".
-spec icmpv6_accept() -> rule().
icmpv6_accept() ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?ICMPV6>>),
     nft_expr_ir:payload(transport, 0, 1, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?ICMPV6_ECHO_REQUEST>>),
     nft_expr_ir:accept()].

-doc "Accept all traffic of the given protocol.".
-spec protocol_accept(atom() | 0..255) -> rule().
protocol_accept(Proto) ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<(proto_num(Proto))>>),
     nft_expr_ir:accept()].

-doc "Accept traffic from a specific source address (4 or 16 byte binary).".
-spec ip_saddr_accept(binary()) -> rule().
ip_saddr_accept(IP) when byte_size(IP) =:= 4 ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
     nft_expr_ir:ip_saddr(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, IP),
     nft_expr_ir:accept()];
ip_saddr_accept(IP) when byte_size(IP) =:= 16 ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
     nft_expr_ir:ip6_saddr(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, IP),
     nft_expr_ir:accept()].

-doc "Drop traffic from a specific source address (4 or 16 byte binary).".
-spec ip_saddr_drop(binary()) -> rule().
ip_saddr_drop(IP) when byte_size(IP) =:= 4 ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
     nft_expr_ir:ip_saddr(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, IP),
     nft_expr_ir:drop()];
ip_saddr_drop(IP) when byte_size(IP) =:= 16 ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
     nft_expr_ir:ip6_saddr(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, IP),
     nft_expr_ir:drop()].

-doc "Drop if source IP is in the named set (IPv4).".
-spec set_lookup_drop(binary()) -> rule().
set_lookup_drop(SetName) ->
    set_lookup_drop(SetName, ipv4_addr).

-doc "Drop if source IP is in the named set with explicit address type.".
-spec set_lookup_drop(binary(), ipv4_addr | ipv6_addr) -> rule().
set_lookup_drop(SetName, ipv4_addr) ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
     nft_expr_ir:ip_saddr(?REG1),
     nft_expr_ir:lookup(?REG1, SetName),
     nft_expr_ir:drop()];
set_lookup_drop(SetName, ipv6_addr) ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
     nft_expr_ir:ip6_saddr(?REG1),
     nft_expr_ir:lookup(?REG1, SetName),
     nft_expr_ir:drop()].

-doc "Drop from set with a named counter (IPv4).".
-spec set_lookup_drop_named(binary(), binary()) -> rule().
set_lookup_drop_named(SetName, CounterName) ->
    set_lookup_drop_named(SetName, CounterName, ipv4_addr).

-doc "Drop from set with a named counter and explicit address type.".
-spec set_lookup_drop_named(binary(), binary(), ipv4_addr | ipv6_addr) -> rule().
set_lookup_drop_named(SetName, CounterName, ipv4_addr) ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
     nft_expr_ir:ip_saddr(?REG1),
     nft_expr_ir:lookup(?REG1, SetName),
     nft_expr_ir:objref_counter(CounterName),
     nft_expr_ir:drop()];
set_lookup_drop_named(SetName, CounterName, ipv6_addr) ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
     nft_expr_ir:ip6_saddr(?REG1),
     nft_expr_ir:lookup(?REG1, SetName),
     nft_expr_ir:objref_counter(CounterName),
     nft_expr_ir:drop()].

-doc "Drop when concurrent connections exceed Count. Flags: 0=over, 1=invert.".
-spec connlimit_drop(non_neg_integer(), non_neg_integer()) -> rule().
connlimit_drop(Count, Flags) ->
    [nft_expr_ir:connlimit(Count, Flags),
     nft_expr_ir:drop()].

-doc "Log and drop all unmatched traffic.".
-spec log_drop(binary()) -> rule().
log_drop(Prefix) ->
    [nft_expr_ir:log(#{prefix => Prefix}),
     nft_expr_ir:drop()].

-doc "Log and drop with a named counter.".
-spec log_drop_named(binary(), binary()) -> rule().
log_drop_named(Prefix, CounterName) ->
    [nft_expr_ir:objref_counter(CounterName),
     nft_expr_ir:log(#{prefix => Prefix}),
     nft_expr_ir:drop()].

-doc "Log to NFLOG group, count, and drop.".
-spec log_drop_nflog(binary(), non_neg_integer(), binary()) -> rule().
log_drop_nflog(Prefix, Group, CounterName) ->
    [nft_expr_ir:objref_counter(CounterName),
     nft_expr_ir:log(#{prefix => Prefix, group => Group}),
     nft_expr_ir:drop()].

-doc "Log and reject with ICMP unreachable (instead of silent drop).".
-spec log_reject(binary()) -> rule().
log_reject(Prefix) ->
    [nft_expr_ir:log(#{prefix => Prefix}),
     nft_expr_ir:reject()].

-doc "Masquerade outgoing traffic (dynamic SNAT for NAT gateways).".
-spec masq_rule() -> rule().
masq_rule() ->
    [nft_expr_ir:masq()].

-doc "Masquerade traffic leaving via any interface except the named one.".
-spec oifname_neq_masq(binary()) -> rule().
oifname_neq_masq(IfName) ->
    Padded = pad_ifname(IfName),
    [nft_expr_ir:meta(oifname, ?REG1),
     nft_expr_ir:cmp(neq, ?REG1, Padded),
     nft_expr_ir:masq()].

-doc """
Destination NAT: forward traffic to an internal IP and port.
IP is a 4 or 16 byte binary, Port is 0..65535.
Loads the address and port into registers, then applies DNAT.
""".
-spec dnat_rule(binary(), 0..65535) -> rule().
dnat_rule(IP, Port) when byte_size(IP) =:= 4; byte_size(IP) =:= 16 ->
    Family = ip_family(IP),
    [nft_expr_ir:immediate_data(?REG1, IP),
     nft_expr_ir:immediate_data(?REG2, <<Port:16/big>>),
     nft_expr_ir:dnat(?REG1, ?REG2, Family)].

-doc "DNAT TCP traffic on MatchPort to DstIp:DstPort.".
-spec tcp_dnat(0..65535, binary(), 0..65535) -> rule().
tcp_dnat(MatchPort, DstIp, DstPort)
  when byte_size(DstIp) =:= 4; byte_size(DstIp) =:= 16 ->
    Family = ip_family(DstIp),
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?TCP>>),
     nft_expr_ir:tcp_dport(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<MatchPort:16/big>>),
     nft_expr_ir:immediate_data(?REG1, DstIp),
     nft_expr_ir:immediate_data(?REG2, <<DstPort:16/big>>),
     nft_expr_ir:dnat(?REG1, ?REG2, Family)].

-doc """
Accept UDP traffic on a port if source IP is in the named set.

Used for WireGuard SPA: only allow UDP 51820 if the client's IP
has been authorized via SPA and added to the allowlist set.
""".
-spec set_lookup_udp_accept(binary(), 0..65535, ipv4_addr | ipv6_addr) -> rule().
set_lookup_udp_accept(SetName, Port, ipv4_addr) ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV4>>),
     nft_expr_ir:meta(l4proto, ?REG2),
     nft_expr_ir:cmp(eq, ?REG2, <<?UDP>>),
     nft_expr_ir:udp_dport(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
     nft_expr_ir:ip_saddr(?REG1),
     nft_expr_ir:lookup(?REG1, SetName),
     nft_expr_ir:accept()];
set_lookup_udp_accept(SetName, Port, ipv6_addr) ->
    [nft_expr_ir:meta(nfproto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?NFPROTO_IPV6>>),
     nft_expr_ir:meta(l4proto, ?REG2),
     nft_expr_ir:cmp(eq, ?REG2, <<?UDP>>),
     nft_expr_ir:udp_dport(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
     nft_expr_ir:ip6_saddr(?REG1),
     nft_expr_ir:lookup(?REG1, SetName),
     nft_expr_ir:accept()].

-doc """
Capture a UDP packet on a port via NFLOG and drop it.

Used for SPA: the UDP packet on the SPA port is logged to an NFLOG
group for userspace processing, then dropped so it never reaches
the target service.
""".
-spec nflog_capture_udp(0..65535, binary(), non_neg_integer()) -> rule().
nflog_capture_udp(Port, Prefix, Group) ->
    [nft_expr_ir:meta(l4proto, ?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<?UDP>>),
     nft_expr_ir:udp_dport(?REG1),
     nft_expr_ir:cmp(eq, ?REG1, <<Port:16/big>>),
     nft_expr_ir:log(#{prefix => Prefix, group => Group, snaplen => 128}),
     nft_expr_ir:drop()].

%% --- Set Element Operations (msg_funs, not terms) ---

-doc "Add an IP address to a named set (ban).".
-spec ban_ip(binary(), binary(), binary()) -> fun((non_neg_integer()) -> binary()).
ban_ip(Table, SetName, IP) when byte_size(IP) =:= 4; byte_size(IP) =:= 16 ->
    fun(Seq) ->
        nft_set_elem:add(?INET, Table, SetName, IP, Seq)
    end.

-doc "Remove an IP address from a named set (unban).".
-spec unban_ip(binary(), binary(), binary()) -> fun((non_neg_integer()) -> binary()).
unban_ip(Table, SetName, IP) when byte_size(IP) =:= 4; byte_size(IP) =:= 16 ->
    fun(Seq) ->
        nft_set_elem:del(?INET, Table, SetName, IP, Seq)
    end.

%% --- Internal ---

-spec proto_num(atom() | 0..255) -> 0..255.
proto_num(icmp)   -> 1;
proto_num(tcp)    -> 6;
proto_num(udp)    -> 17;
proto_num(icmpv6) -> 58;
proto_num(N) when is_integer(N), N >= 0, N =< 255 -> N.

-spec pad_ifname(binary()) -> binary().
pad_ifname(Name) when byte_size(Name) =< 16 ->
    Pad = 16 - byte_size(Name),
    <<Name/binary, 0:(Pad * 8)>>.

%% NFPROTO_IPV4 = 2, NFPROTO_IPV6 = 10
ip_family(IP) when byte_size(IP) =:= 4  -> 2;
ip_family(IP) when byte_size(IP) =:= 16 -> 10.
