-module(nft_rules_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

all() ->
    [
        ct_established_has_bitwise,
        tcp_accept_port_encoding,
        udp_accept_port_encoding,
        protocol_accept_icmp,
        protocol_accept_numeric,
        iif_accept_loopback,
        full_firewall_msgs,
        %% New rule helpers
        forward_established_test,
        iifname_accept_test,
        tcp_port_range_accept_test,
        tcp_reject_test,
        udp_accept_limited_test,
        udp_port_range_accept_test,
        icmp_accept_test,
        icmpv6_accept_test,
        ip_saddr_accept_test,
        ip_saddr_drop_test,
        connlimit_drop_test,
        log_reject_test,
        masq_rule_test,
        dnat_rule_test,
        %% IPv6 tests
        set_lookup_drop_ipv6_test,
        ip_saddr_accept_ipv6_test,
        ban_ip_ipv6_test,
        dnat_rule_ipv6_test,
        set_lookup_udp_accept_ipv4_test,
        set_lookup_udp_accept_ipv6_test,
        nflog_capture_udp_test,
        iifname_jump_test,
        oifname_accept_test,
        oifname_neq_masq_test,
        iifname_oifname_jump_test,
        iifname_oifname_masq_test
    ].

ct_established_has_bitwise(_) ->
    Rule = nft_rules:ct_established_accept(),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    {4, nested, Exprs} = lists:keyfind(4, 1, Decoded),
    ?assertEqual(4, length(Exprs)),
    {1, nested, CtOuter} = lists:nth(1, Exprs),
    {1, <<"ct", 0>>} = lists:keyfind(1, 1, CtOuter),
    {1, nested, BwOuter} = lists:nth(2, Exprs),
    {1, <<"bitwise", 0>>} = lists:keyfind(1, 1, BwOuter).

tcp_accept_port_encoding(_) ->
    Rule = nft_rules:tcp_accept(443),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    ?assertNotEqual(nomatch, binary:match(Msg, <<1, 187>>)).

udp_accept_port_encoding(_) ->
    Rule = nft_rules:udp_accept(53),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    ?assertNotEqual(nomatch, binary:match(Msg, <<17>>)).

protocol_accept_icmp(_) ->
    Rule = nft_rules:protocol_accept(icmp),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    ?assert(is_binary(Msg)).

protocol_accept_numeric(_) ->
    Rule = nft_rules:protocol_accept(47),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    ?assert(is_binary(Msg)).

iif_accept_loopback(_) ->
    Rule = nft_rules:iif_accept(),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    ?assert(is_binary(Msg)),
    %% Verify the meta expression encodes key=4 (NFT_META_IIF), not 8 (IIFTYPE bug)
    MetaExpr = nft_encode:expr(hd(Rule)),
    ?assertNotEqual(nomatch, binary:match(MetaExpr, <<4:32/big>>)),
    ?assertEqual(nomatch, binary:match(MetaExpr, <<8:32/big>>)).

full_firewall_msgs(_) ->
    T = <<"fw">>,
    I = <<"input">>,
    Rules = [
        nft_rules:ct_established_accept(),
        nft_rules:iif_accept(),
        nft_rules:tcp_accept(22),
        nft_rules:tcp_accept(80),
        nft_rules:tcp_accept(443),
        nft_rules:protocol_accept(icmp),
        nft_rules:protocol_accept(icmpv6)
    ],
    Funs = [nft_encode:rule_fun(inet, T, I, R) || R <- Rules],
    Msgs = [F(N) || {F, N} <- lists:zip(Funs, lists:seq(1, length(Funs)))],
    lists:foreach(
        fun(M) ->
            ?assert(is_binary(M)),
            ?assert(byte_size(M) > 20)
        end,
        Msgs
    ).

%% ===================================================================
%% New rule helper tests
%% ===================================================================

forward_established_test(_) ->
    Rule = nft_rules:forward_established(),
    %% Same as ct_established_accept — 4 expressions: ct, bitwise, cmp, accept
    ?assertEqual(4, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"ct">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"bitwise">>)).

iifname_accept_test(_) ->
    Rule = nft_rules:iifname_accept(<<"br0">>),
    ?assertEqual(3, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"meta">>)),
    %% Interface name should appear padded in the binary
    ?assertNotEqual(nomatch, binary:match(Msg, <<"br0">>)).

tcp_port_range_accept_test(_) ->
    Rule = nft_rules:tcp_port_range_accept(1024, 65535),
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"range">>)),
    %% Port 1024 = <<4, 0>>, Port 65535 = <<255, 255>>
    ?assertNotEqual(nomatch, binary:match(Msg, <<4, 0>>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<255, 255>>)).

tcp_reject_test(_) ->
    Rule = nft_rules:tcp_reject(8080),
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"reject">>)),
    %% Port 8080 = <<31, 144>>
    ?assertNotEqual(nomatch, binary:match(Msg, <<31, 144>>)).

udp_accept_limited_test(_) ->
    [DropRule, AcceptRule] = nft_rules:udp_accept_limited(
        53,
        <<"dns">>,
        #{rate => 100, burst => 50}
    ),
    %% Drop rule: meta, cmp, payload, cmp, limit, drop = 6
    ?assertEqual(6, length(DropRule)),
    %% Accept rule: meta, cmp, payload, cmp, objref, accept = 6
    ?assertEqual(6, length(AcceptRule)),
    DropMsg = encode_rule(DropRule),
    ?assertNotEqual(nomatch, binary:match(DropMsg, <<"limit">>)),
    AcceptMsg = encode_rule(AcceptRule),
    ?assertNotEqual(nomatch, binary:match(AcceptMsg, <<"objref">>)).

udp_port_range_accept_test(_) ->
    Rule = nft_rules:udp_port_range_accept(10000, 20000),
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"range">>)).

icmp_accept_test(_) ->
    Rule = nft_rules:icmp_accept(),
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    %% ICMP protocol = 1, echo request type = 8
    ?assertNotEqual(nomatch, binary:match(Msg, <<"payload">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"immediate">>)).

icmpv6_accept_test(_) ->
    Rule = nft_rules:icmpv6_accept(),
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    %% ICMPv6 protocol = 58
    ?assertNotEqual(nomatch, binary:match(Msg, <<58>>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"immediate">>)).

ip_saddr_accept_test(_) ->
    IP = <<10, 0, 0, 1>>,
    Rule = nft_rules:ip_saddr_accept(IP),
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<10, 0, 0, 1>>)).

ip_saddr_drop_test(_) ->
    IP = <<192, 168, 1, 100>>,
    Rule = nft_rules:ip_saddr_drop(IP),
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<192, 168, 1, 100>>)).

connlimit_drop_test(_) ->
    Rule = nft_rules:connlimit_drop(100, 0),
    ?assertEqual(2, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"connlimit">>)).

log_reject_test(_) ->
    Rule = nft_rules:log_reject(<<"REJECTED: ">>),
    ?assertEqual(2, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"log">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"reject">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"REJECTED: ">>)).

masq_rule_test(_) ->
    Rule = nft_rules:masq_rule(),
    ?assertEqual(1, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"masq">>)).

dnat_rule_test(_) ->
    IP = <<10, 0, 0, 50>>,
    Rule = nft_rules:dnat_rule(IP, 8080),
    ?assertEqual(3, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"nat">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"immediate">>)),
    %% The target IP should appear in the message
    ?assertNotEqual(nomatch, binary:match(Msg, <<10, 0, 0, 50>>)).

%% ===================================================================
%% IPv6 tests
%% ===================================================================

set_lookup_drop_ipv6_test(_) ->
    Rule = nft_rules:set_lookup_drop(<<"blocklist6">>, ipv6_addr),
    %% 5 exprs: meta nfproto, cmp, ip6_saddr, lookup, drop
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    %% nfproto=10 should appear
    ?assertNotEqual(nomatch, binary:match(Msg, <<10>>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"blocklist6">>)).

ip_saddr_accept_ipv6_test(_) ->
    IP = <<16#2001:16, 16#0db8:16, 0:80, 1:16>>,
    Rule = nft_rules:ip_saddr_accept(IP),
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    %% The 16-byte IPv6 address should be in the message
    ?assertNotEqual(nomatch, binary:match(Msg, IP)).

ban_ip_ipv6_test(_) ->
    IP = <<16#2001:16, 16#0db8:16, 0:80, 5:16>>,
    Fun = nft_rules:ban_ip(<<"t">>, <<"blocklist6">>, IP),
    Msg = Fun(1),
    ?assert(is_binary(Msg)),
    ?assertNotEqual(nomatch, binary:match(Msg, IP)).

dnat_rule_ipv6_test(_) ->
    IP = <<16#2001:16, 16#0db8:16, 0:80, 50:16>>,
    Rule = nft_rules:dnat_rule(IP, 8080),
    ?assertEqual(3, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, IP)).

%% ===================================================================
%% WireGuard SPA tests
%% ===================================================================

set_lookup_udp_accept_ipv4_test(_) ->
    Rule = nft_rules:set_lookup_udp_accept(<<"wg_allow">>, 51820, ipv4_addr),
    %% 9 exprs: meta nfproto, cmp, meta l4proto, cmp, udp_dport, cmp, ip_saddr, lookup, accept
    ?assertEqual(9, length(Rule)),
    Msg = encode_rule(Rule),
    %% Set name should appear
    ?assertNotEqual(nomatch, binary:match(Msg, <<"wg_allow">>)),
    %% Port 51820 = <<0xCA, 0x6C>>
    ?assertNotEqual(nomatch, binary:match(Msg, <<51820:16/big>>)).

set_lookup_udp_accept_ipv6_test(_) ->
    Rule = nft_rules:set_lookup_udp_accept(<<"wg_allow6">>, 51820, ipv6_addr),
    ?assertEqual(9, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"wg_allow6">>)),
    %% nfproto=10 (IPv6)
    ?assertNotEqual(nomatch, binary:match(Msg, <<10>>)).

nflog_capture_udp_test(_) ->
    Rule = nft_rules:nflog_capture_udp(61820, <<"SPA:">>, 3),
    %% 6 exprs: meta l4proto, cmp, udp_dport, cmp, log, drop
    ?assertEqual(6, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"SPA:">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"log">>)),
    %% Port 61820 = <<0xF1, 0x7C>>
    ?assertNotEqual(nomatch, binary:match(Msg, <<61820:16/big>>)).

%% ===================================================================
%% Interface-pair rule tests
%% ===================================================================

iifname_jump_test(_) ->
    Rule = nft_rules:iifname_jump(<<"eth0">>, <<"input_wan">>),
    %% 3 exprs: meta iifname, cmp, jump
    ?assertEqual(3, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"eth0">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"immediate">>)).

oifname_accept_test(_) ->
    Rule = nft_rules:oifname_accept(<<"eth0">>),
    ?assertEqual(3, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"eth0">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"meta">>)).

oifname_neq_masq_test(_) ->
    Rule = nft_rules:oifname_neq_masq(<<"wg0">>),
    ?assertEqual(3, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"wg0">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"masq">>)).

iifname_oifname_jump_test(_) ->
    Rule = nft_rules:iifname_oifname_jump(<<"eth1">>, <<"eth0">>, <<"fwd_lan_wan">>),
    %% 5 exprs: meta iifname, cmp, meta oifname, cmp, jump
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"eth1">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"eth0">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"immediate">>)).

iifname_oifname_masq_test(_) ->
    Rule = nft_rules:iifname_oifname_masq(<<"eth1">>, <<"eth0">>),
    %% 5 exprs: meta iifname, cmp, meta oifname, cmp, masq
    ?assertEqual(5, length(Rule)),
    Msg = encode_rule(Rule),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"eth1">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"eth0">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"masq">>)).

%% --- Helpers ---

encode_rule(Rule) ->
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Fun(1).
