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

-module(nft_vm_pkt).
-moduledoc """
Packet builder for the nft_vm simulator.

Constructs synthetic packets for testing nf_tables rules without
touching the kernel. Each builder creates a packet map with the
correct layer headers, metadata, and conntrack state.

Example:
    %% SSH SYN packet from 192.168.1.100 to 10.0.0.1
    Pkt = nft_vm_pkt:tcp(
        #{saddr => {192,168,1,100}, daddr => {10,0,0,1}},
        #{sport => 54321, dport => 22, flags => syn}),

    %% Established TCP connection
    Pkt = nft_vm_pkt:tcp(
        #{saddr => {192,168,1,100}, daddr => {10,0,0,1}},
        #{sport => 54321, dport => 80, flags => ack},
        #{ct_state => established}),

    %% ICMP ping
    Pkt = nft_vm_pkt:icmp(
        #{saddr => {192,168,1,100}, daddr => {10,0,0,1}},
        #{type => echo_request}),

    %% Loopback traffic
    Pkt = nft_vm_pkt:tcp(
        #{saddr => {127,0,0,1}, daddr => {127,0,0,1}},
        #{sport => 8080, dport => 80},
        #{iif => 1, iifname => <<"lo">>})
""".

-export([tcp/2, tcp/3,
         udp/2, udp/3,
         icmp/2, icmp/3,
         raw/1,
         with_sets/2,
         with_limit_state/2]).

%% --- Constants ---

%% Conntrack state bits (matching kernel nf_conntrack_common.h)
-define(CT_NEW,               16#08).
-define(CT_ESTABLISHED,       16#02).
-define(CT_RELATED,           16#04).
-define(CT_ESTABLISHED_REPLY, 16#20).

%% IP protocol numbers
-define(IPPROTO_ICMP,  1).
-define(IPPROTO_TCP,   6).
-define(IPPROTO_UDP,  17).

%% --- Public API ---

-doc """
Build a TCP packet.

IpOpts: saddr, daddr (tuple or binary)
TcpOpts: sport, dport, flags (syn|ack|fin|rst|psh), seq, ack_num, window
""".
-spec tcp(map(), map()) -> nft_vm:packet().
tcp(IpOpts, TcpOpts) ->
    tcp(IpOpts, TcpOpts, #{}).

-doc "Build a TCP packet with explicit metadata (iif, ct_state, etc.).".
-spec tcp(map(), map(), map()) -> nft_vm:packet().
tcp(IpOpts, TcpOpts, Meta) ->
    Sport = maps:get(sport, TcpOpts, 0),
    Dport = maps:get(dport, TcpOpts, 0),
    Flags = tcp_flags(maps:get(flags, TcpOpts, none)),
    Seq = maps:get(seq, TcpOpts, 0),
    AckNum = maps:get(ack_num, TcpOpts, 0),
    Window = maps:get(window, TcpOpts, 65535),
    DataOffset = 5,
    TcpHeader = <<Sport:16/big, Dport:16/big,
                  Seq:32/big,
                  AckNum:32/big,
                  DataOffset:4, 0:6, Flags:6,
                  Window:16/big,
                  0:16, 0:16>>,  %% checksum, urgent ptr

    IpHeader = build_ip_header(IpOpts, ?IPPROTO_TCP, byte_size(TcpHeader)),

    CtState = maps:get(ct_state, Meta, ct_from_flags(maps:get(flags, TcpOpts, none))),
    base_packet(IpHeader, TcpHeader, ?IPPROTO_TCP, IpOpts, Meta, CtState).

-doc "Build a UDP packet.".
-spec udp(map(), map()) -> nft_vm:packet().
udp(IpOpts, UdpOpts) ->
    udp(IpOpts, UdpOpts, #{}).

-doc "Build a UDP packet with explicit metadata.".
-spec udp(map(), map(), map()) -> nft_vm:packet().
udp(IpOpts, UdpOpts, Meta) ->
    Sport = maps:get(sport, UdpOpts, 0),
    Dport = maps:get(dport, UdpOpts, 0),
    Payload = maps:get(payload, UdpOpts, <<>>),
    Len = 8 + byte_size(Payload),
    UdpHeader = <<Sport:16/big, Dport:16/big,
                  Len:16/big, 0:16,  %% length, checksum
                  Payload/binary>>,

    IpHeader = build_ip_header(IpOpts, ?IPPROTO_UDP, byte_size(UdpHeader)),

    CtState = maps:get(ct_state, Meta, ?CT_NEW),
    base_packet(IpHeader, UdpHeader, ?IPPROTO_UDP, IpOpts, Meta, CtState).

-doc "Build an ICMP packet.".
-spec icmp(map(), map()) -> nft_vm:packet().
icmp(IpOpts, IcmpOpts) ->
    icmp(IpOpts, IcmpOpts, #{}).

-doc "Build an ICMP packet with explicit metadata.".
-spec icmp(map(), map(), map()) -> nft_vm:packet().
icmp(IpOpts, IcmpOpts, Meta) ->
    Type = icmp_type(maps:get(type, IcmpOpts, echo_request)),
    Code = maps:get(code, IcmpOpts, 0),
    Id   = maps:get(id, IcmpOpts, 1),
    SeqN = maps:get(seq, IcmpOpts, 1),
    IcmpHeader = <<Type:8, Code:8, 0:16,  %% type, code, checksum
                   Id:16/big, SeqN:16/big>>,

    IpHeader = build_ip_header(IpOpts, ?IPPROTO_ICMP, byte_size(IcmpHeader)),

    CtState = maps:get(ct_state, Meta, ?CT_NEW),
    base_packet(IpHeader, IcmpHeader, ?IPPROTO_ICMP, IpOpts, Meta, CtState).

-doc """
Build a raw packet from a map. Useful for edge cases.

Must contain at minimum: network, transport, l4proto, nfproto.
""".
-spec raw(map()) -> nft_vm:packet().
raw(Map) ->
    Defaults = #{
        network => <<>>, transport => <<>>, link => <<>>,
        nfproto => 2, l4proto => 0,
        iif => 0, oif => 0,
        iifname => <<>>, oifname => <<>>,
        len => 0, mark => 0,
        ct_state => 0, ct_mark => 0, ct_status => 0,
        sets => #{}
    },
    maps:merge(Defaults, Map).

-doc """
Add set membership data to a packet for lookup expression testing.

Sets is a map of set_name => [binary()] elements.

Example:
    Pkt1 = nft_vm_pkt:tcp(IpOpts, TcpOpts),
    Pkt2 = nft_vm_pkt:with_sets(Pkt1, #{
        <<"blocklist">> => [<<10,0,0,5>>, <<10,0,0,6>>]
    })
""".
-spec with_sets(nft_vm:packet(), #{binary() => [binary()]}) -> nft_vm:packet().
with_sets(Pkt, SetMap) ->
    Sets = maps:fold(fun(Name, Elements, Acc) ->
        Acc#{Name => sets:from_list(Elements)}
    end, maps:get(sets, Pkt, #{}), SetMap),
    Pkt#{sets => Sets}.

-doc """
Set rate limit simulation state.

LimitState maps limit names (or 'default') to booleans.
true = over the limit, false = under.

Example:
    Pkt2 = nft_vm_pkt:with_limit_state(Pkt1, #{default => true})
""".
-spec with_limit_state(nft_vm:packet(), map()) -> nft_vm:packet().
with_limit_state(Pkt, LimitState) ->
    Pkt#{limit_state => LimitState}.

%% --- Internal ---

build_ip_header(IpOpts, Protocol, PayloadLen) ->
    Saddr = ip_to_bin(maps:get(saddr, IpOpts, {0,0,0,0})),
    case byte_size(Saddr) of
        4 ->
            Daddr = ip_to_bin(maps:get(daddr, IpOpts, {0,0,0,0})),
            build_ipv4_header(Saddr, Daddr, IpOpts, Protocol, PayloadLen);
        16 ->
            Daddr = ip_to_bin(maps:get(daddr, IpOpts, {0,0,0,0,0,0,0,0})),
            build_ipv6_header(Saddr, Daddr, IpOpts, Protocol, PayloadLen)
    end.

build_ipv4_header(Saddr, Daddr, IpOpts, Protocol, PayloadLen) ->
    Ttl = maps:get(ttl, IpOpts, 64),
    TotalLen = 20 + PayloadLen,
    <<4:4, 5:4, 0:8,                    %% version, IHL, DSCP/ECN
      TotalLen:16/big,                    %% total length
      0:16, 0:16,                         %% identification, flags/fragment
      Ttl:8, Protocol:8, 0:16,           %% TTL, protocol, checksum
      Saddr:4/binary,                     %% source address
      Daddr:4/binary>>.                   %% destination address

build_ipv6_header(Saddr, Daddr, IpOpts, NextHeader, PayloadLen) ->
    HopLimit = maps:get(ttl, IpOpts, 64),
    <<6:4, 0:8, 0:20,                    %% version, traffic class, flow label
      PayloadLen:16/big,                  %% payload length
      NextHeader:8, HopLimit:8,           %% next header, hop limit
      Saddr:16/binary,                    %% source address
      Daddr:16/binary>>.                  %% destination address

base_packet(IpHeader, TransportHeader, L4Proto, _IpOpts, Meta, CtState) ->
    TotalLen = byte_size(IpHeader) + byte_size(TransportHeader),
    NfProto = case IpHeader of
        <<4:4, _/bitstring>> -> 2;   %% IPv4
        <<6:4, _/bitstring>> -> 10;  %% IPv6
        _ -> 2
    end,
    #{
        network    => IpHeader,
        transport  => TransportHeader,
        link       => <<>>,
        nfproto    => NfProto,
        l4proto    => L4Proto,
        iif        => maps:get(iif, Meta, 0),
        oif        => maps:get(oif, Meta, 0),
        iifname    => maps:get(iifname, Meta, <<>>),
        oifname    => maps:get(oifname, Meta, <<>>),
        len        => TotalLen,
        mark       => maps:get(mark, Meta, 0),
        ct_state   => ct_val(CtState),
        ct_mark    => maps:get(ct_mark, Meta, 0),
        ct_status  => maps:get(ct_status, Meta, 0),
        sets       => maps:get(sets, Meta, #{})
    }.

ip_to_bin({A, B, C, D}) -> <<A, B, C, D>>;
ip_to_bin({A, B, C, D, E, F, G, H}) -> <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>;
ip_to_bin(Bin) when is_binary(Bin), byte_size(Bin) =:= 4 -> Bin;
ip_to_bin(Bin) when is_binary(Bin), byte_size(Bin) =:= 16 -> Bin.

tcp_flags(syn)     -> 2#000010;
tcp_flags(ack)     -> 2#010000;
tcp_flags(fin)     -> 2#000001;
tcp_flags(rst)     -> 2#000100;
tcp_flags(psh)     -> 2#001000;
tcp_flags(syn_ack) -> 2#010010;
tcp_flags(fin_ack) -> 2#010001;
tcp_flags(none)    -> 0;
tcp_flags(N) when is_integer(N) -> N.

ct_from_flags(syn)  -> ?CT_NEW;
ct_from_flags(ack)  -> ?CT_ESTABLISHED;
ct_from_flags(syn_ack) -> ?CT_ESTABLISHED;
ct_from_flags(_)    -> ?CT_NEW.

ct_val(new)              -> ?CT_NEW;
ct_val(established)      -> ?CT_ESTABLISHED;
ct_val(related)          -> ?CT_RELATED;
ct_val(established_reply) -> ?CT_ESTABLISHED_REPLY;
ct_val(N) when is_integer(N) -> N.

icmp_type(echo_request) -> 8;
icmp_type(echo_reply)   -> 0;
icmp_type(dest_unreachable) -> 3;
icmp_type(time_exceeded) -> 11;
icmp_type(N) when is_integer(N) -> N.
