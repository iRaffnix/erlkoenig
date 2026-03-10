-module(nft_vm_SUITE).
-moduledoc """
nft_vm integration tests for Erlkönig.

Tests the actual IR-based firewall rules from nft_rules.erl through
the VM simulator — proving rule logic is correct without touching
the kernel.

Requires the IR-based nft_rules.erl (returns expression term lists,
not msg_funs).
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1]).
-export([
    %% Expression tests
    test_meta_l4proto/1, test_meta_nfproto/1, test_meta_iif/1,
    test_payload_tcp_dport/1, test_payload_ip_saddr/1, test_payload_ip6_saddr/1,
    test_cmp_eq_match/1, test_cmp_eq_no_match/1, test_cmp_neq/1, test_cmp_lt_gt/1,
    test_bitwise_mask/1, test_ct_state/1,
    test_immediate_accept/1, test_immediate_drop/1,
    test_lookup_match/1, test_lookup_no_match/1, test_lookup_inverted/1,
    test_range_match/1, test_range_no_match/1,
    test_limit_under/1, test_limit_over/1, test_limit_inverted/1,
    %% nft_rules integration (calls nft_rules directly)
    test_nft_rules_ct_established/1, test_nft_rules_ct_new_rejected/1,
    test_nft_rules_iif_accept/1, test_nft_rules_iif_reject/1,
    test_nft_rules_tcp_accept/1, test_nft_rules_tcp_wrong_port/1,
    test_nft_rules_tcp_named/1,
    test_nft_rules_tcp_limited_under/1, test_nft_rules_tcp_limited_over/1,
    test_nft_rules_udp_accept/1, test_nft_rules_udp_wrong_proto/1,
    test_nft_rules_protocol_icmp/1,
    test_nft_rules_set_lookup_drop/1, test_nft_rules_set_lookup_miss/1,
    test_nft_rules_log_drop/1,
    %% Chain simulation
    test_chain_erlkoenig_firewall/1,
    test_chain_ssh_bruteforce/1,
    test_chain_default_policy/1,
    test_chain_first_match_wins/1,
    %% IPv6
    test_ipv6_nfproto/1,
    test_ipv6_set_lookup_drop/1,
    test_ipv6_dual_stack_chain/1,
    %% IR compat
    test_ir_produces_vm_terms/1,
    test_ir_nat_tuple/1,
    test_ir_generic_tuple/1,
    %% Trace
    test_trace_printing/1,
    %% WireGuard SPA
    test_wg_blocked_without_auth/1,
    test_wg_allowed_with_auth/1,
    test_wg_spa_captured/1,
    test_wg_established_continues/1
]).

all() ->
    [{group, expressions},
     {group, nft_rules},
     {group, chains},
     {group, ir_compat},
     {group, trace},
     {group, wireguard}].

groups() ->
    [{expressions, [parallel], [
        test_meta_l4proto, test_meta_nfproto, test_meta_iif,
        test_payload_tcp_dport, test_payload_ip_saddr, test_payload_ip6_saddr,
        test_cmp_eq_match, test_cmp_eq_no_match, test_cmp_neq, test_cmp_lt_gt,
        test_bitwise_mask, test_ct_state,
        test_immediate_accept, test_immediate_drop,
        test_lookup_match, test_lookup_no_match, test_lookup_inverted,
        test_range_match, test_range_no_match,
        test_limit_under, test_limit_over, test_limit_inverted
     ]},
     {nft_rules, [parallel], [
        test_nft_rules_ct_established, test_nft_rules_ct_new_rejected,
        test_nft_rules_iif_accept, test_nft_rules_iif_reject,
        test_nft_rules_tcp_accept, test_nft_rules_tcp_wrong_port,
        test_nft_rules_tcp_named,
        test_nft_rules_tcp_limited_under, test_nft_rules_tcp_limited_over,
        test_nft_rules_udp_accept, test_nft_rules_udp_wrong_proto,
        test_nft_rules_protocol_icmp,
        test_nft_rules_set_lookup_drop, test_nft_rules_set_lookup_miss,
        test_nft_rules_log_drop
     ]},
     {chains, [parallel], [
        test_chain_erlkoenig_firewall,
        test_chain_ssh_bruteforce,
        test_chain_default_policy,
        test_chain_first_match_wins,
        test_ipv6_nfproto,
        test_ipv6_set_lookup_drop,
        test_ipv6_dual_stack_chain
     ]},
     {ir_compat, [parallel], [
        test_ir_produces_vm_terms,
        test_ir_nat_tuple,
        test_ir_generic_tuple
     ]},
     {trace, [], [
        test_trace_printing
     ]},
     {wireguard, [parallel], [
        test_wg_blocked_without_auth,
        test_wg_allowed_with_auth,
        test_wg_spa_captured,
        test_wg_established_continues
     ]}].

init_per_suite(Config) ->
    %% Verify the IR-based nft_rules is loaded (not the old msg_fun version)
    {module, nft_rules} = code:ensure_loaded(nft_rules),
    Exports = nft_rules:module_info(exports),
    %% IR version has tcp_accept/1, old version has tcp_accept/3
    case lists:member({tcp_accept, 1}, Exports) of
        true ->
            ok;
        false ->
            ct:fail("nft_rules.erl is the old msg_fun version, not the IR version. "
                    "Deploy the IR-based nft_rules.erl to src/ first.")
    end,
    [code:ensure_loaded(M) || M <- [nft_expr_ir, nft_vm, nft_vm_pkt]],
    Config.

end_per_suite(_Config) ->
    ok.

%% ===================================================================
%% Expression Tests
%% ===================================================================

test_meta_l4proto(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80}),
    {ok, R} = nft_vm:eval_expr({meta, #{key => l4proto, dreg => 1}}, Pkt, new()),
    ?assertEqual(<<6>>, reg(1, R)).

test_meta_nfproto(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80}),
    {ok, R} = nft_vm:eval_expr({meta, #{key => nfproto, dreg => 1}}, Pkt, new()),
    ?assertEqual(<<2>>, reg(1, R)).

test_meta_iif(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {127,0,0,1}}, #{dport => 80}, #{iif => 1}),
    {ok, R} = nft_vm:eval_expr({meta, #{key => iif, dreg => 1}}, Pkt, new()),
    ?assertEqual(<<1:32/native>>, reg(1, R)).

test_payload_tcp_dport(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{sport => 12345, dport => 443}),
    {ok, R} = nft_vm:eval_expr(
        {payload, #{base => transport, offset => 2, len => 2, dreg => 1}}, Pkt, new()),
    ?assertEqual(<<443:16/big>>, reg(1, R)).

test_payload_ip_saddr(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {192,168,1,100}}, #{dport => 80}),
    {ok, R} = nft_vm:eval_expr(
        {payload, #{base => network, offset => 12, len => 4, dreg => 1}}, Pkt, new()),
    ?assertEqual(<<192,168,1,100>>, reg(1, R)).

test_payload_ip6_saddr(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}}, #{dport => 80}),
    %% IPv6 source address is at offset 8, length 16 in the network header
    {ok, R} = nft_vm:eval_expr(
        {payload, #{base => network, offset => 8, len => 16, dreg => 1}}, Pkt, new()),
    Expected = <<16#2001:16, 16#0db8:16, 0:16, 0:16, 0:16, 0:16, 0:16, 1:16>>,
    ?assertEqual(Expected, reg(1, R)).

test_cmp_eq_match(_) ->
    {ok, _} = nft_vm:eval_expr(
        {cmp, #{sreg => 1, op => eq, data => <<6>>}}, #{}, with_reg(1, <<6>>)).

test_cmp_eq_no_match(_) ->
    {break, _} = nft_vm:eval_expr(
        {cmp, #{sreg => 1, op => eq, data => <<6>>}}, #{}, with_reg(1, <<17>>)).

test_cmp_neq(_) ->
    {ok, _} = nft_vm:eval_expr(
        {cmp, #{sreg => 1, op => neq, data => <<6>>}}, #{}, with_reg(1, <<17>>)).

test_cmp_lt_gt(_) ->
    Regs = with_reg(1, <<80:16/big>>),
    {ok, _} = nft_vm:eval_expr(
        {cmp, #{sreg => 1, op => lt, data => <<443:16/big>>}}, #{}, Regs),
    {ok, _} = nft_vm:eval_expr(
        {cmp, #{sreg => 1, op => gt, data => <<22:16/big>>}}, #{}, Regs),
    {break, _} = nft_vm:eval_expr(
        {cmp, #{sreg => 1, op => gt, data => <<443:16/big>>}}, #{}, Regs).

test_bitwise_mask(_) ->
    Regs = with_reg(1, <<16#02:32/native>>),
    {ok, R} = nft_vm:eval_expr(
        {bitwise, #{sreg => 1, dreg => 1,
                    mask => <<16#06:32/native>>, xor_val => <<0:32>>}},
        #{}, Regs),
    ?assertEqual(<<16#02:32/native>>, reg(1, R)).

test_ct_state(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80, flags => ack}),
    {ok, R} = nft_vm:eval_expr({ct, #{key => state, dreg => 1}}, Pkt, new()),
    <<State:32/native>> = reg(1, R),
    ?assert(State band 16#02 =/= 0).

test_immediate_accept(_) ->
    {{verdict, accept}, _} = nft_vm:eval_expr(
        {immediate, #{verdict => accept}}, #{}, new()).

test_immediate_drop(_) ->
    {{verdict, drop}, _} = nft_vm:eval_expr(
        {immediate, #{verdict => drop}}, #{}, new()).

test_lookup_match(_) ->
    Pkt = nft_vm_pkt:with_sets(nft_vm_pkt:raw(#{}),
        #{<<"banned">> => [<<10,0,0,5>>]}),
    {ok, _} = nft_vm:eval_expr(
        {lookup, #{sreg => 1, set => <<"banned">>}}, Pkt, with_reg(1, <<10,0,0,5>>)).

test_lookup_no_match(_) ->
    Pkt = nft_vm_pkt:with_sets(nft_vm_pkt:raw(#{}),
        #{<<"banned">> => [<<10,0,0,5>>]}),
    {break, _} = nft_vm:eval_expr(
        {lookup, #{sreg => 1, set => <<"banned">>}}, Pkt, with_reg(1, <<10,0,0,99>>)).

test_lookup_inverted(_) ->
    Pkt = nft_vm_pkt:with_sets(nft_vm_pkt:raw(#{}),
        #{<<"banned">> => [<<10,0,0,5>>]}),
    {ok, _} = nft_vm:eval_expr(
        {lookup, #{sreg => 1, set => <<"banned">>, flags => 1}}, Pkt, with_reg(1, <<10,0,0,99>>)).

test_range_match(_) ->
    {ok, _} = nft_vm:eval_expr(
        {range, #{sreg => 1, op => eq,
                  from_data => <<1:16/big>>, to_data => <<1024:16/big>>}},
        #{}, with_reg(1, <<80:16/big>>)).

test_range_no_match(_) ->
    {break, _} = nft_vm:eval_expr(
        {range, #{sreg => 1, op => eq,
                  from_data => <<1:16/big>>, to_data => <<1024:16/big>>}},
        #{}, with_reg(1, <<8080:16/big>>)).

test_limit_under(_) ->
    Pkt = nft_vm_pkt:raw(#{limit_state => #{default => false}}),
    {ok, _} = nft_vm:eval_expr({limit, #{rate => 25, flags => 0}}, Pkt, new()).

test_limit_over(_) ->
    Pkt = nft_vm_pkt:raw(#{limit_state => #{default => true}}),
    {break, _} = nft_vm:eval_expr({limit, #{rate => 25, flags => 0}}, Pkt, new()).

test_limit_inverted(_) ->
    Pkt = nft_vm_pkt:raw(#{limit_state => #{default => false}}),
    {break, _} = nft_vm:eval_expr({limit, #{rate => 25, flags => 1}}, Pkt, new()).

%% ===================================================================
%% nft_rules.erl Integration Tests (IR-based version)
%% ===================================================================

test_nft_rules_ct_established(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {192,168,1,100}}, #{dport => 80, flags => ack}),
    {accept, _, _} = nft_vm:eval_rule(nft_rules:ct_established_accept(), Pkt, new()).

test_nft_rules_ct_new_rejected(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {192,168,1,100}}, #{dport => 80, flags => syn}),
    {break, _, _} = nft_vm:eval_rule(nft_rules:ct_established_accept(), Pkt, new()).

test_nft_rules_iif_accept(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {127,0,0,1}}, #{dport => 80}, #{iif => 1}),
    {accept, _, _} = nft_vm:eval_rule(nft_rules:iif_accept(), Pkt, new()).

test_nft_rules_iif_reject(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80}, #{iif => 2}),
    {break, _, _} = nft_vm:eval_rule(nft_rules:iif_accept(), Pkt, new()).

test_nft_rules_tcp_accept(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    {accept, _, _} = nft_vm:eval_rule(nft_rules:tcp_accept(22), Pkt, new()).

test_nft_rules_tcp_wrong_port(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 443}),
    {break, _, _} = nft_vm:eval_rule(nft_rules:tcp_accept(22), Pkt, new()).

test_nft_rules_tcp_named(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80}),
    {accept, _, _} = nft_vm:eval_rule(nft_rules:tcp_accept_named(80, <<"http">>), Pkt, new()).

test_nft_rules_tcp_limited_under(_) ->
    Pkt = nft_vm_pkt:with_limit_state(
        nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
        #{default => false}),
    [DropRule, AcceptRule] = nft_rules:tcp_accept_limited(
        22, <<"ssh">>, #{rate => 25, burst => 5}),
    {accept, _} = nft_vm:eval_chain([DropRule, AcceptRule], Pkt).

test_nft_rules_tcp_limited_over(_) ->
    Pkt = nft_vm_pkt:with_limit_state(
        nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
        #{default => true}),
    [DropRule, AcceptRule] = nft_rules:tcp_accept_limited(
        22, <<"ssh">>, #{rate => 25, burst => 5}),
    {drop, _} = nft_vm:eval_chain([DropRule, AcceptRule], Pkt).

test_nft_rules_udp_accept(_) ->
    Pkt = nft_vm_pkt:udp(#{saddr => {10,0,0,1}}, #{dport => 53}),
    {accept, _, _} = nft_vm:eval_rule(nft_rules:udp_accept(53), Pkt, new()).

test_nft_rules_udp_wrong_proto(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 53}),
    {break, _, _} = nft_vm:eval_rule(nft_rules:udp_accept(53), Pkt, new()).

test_nft_rules_protocol_icmp(_) ->
    Pkt = nft_vm_pkt:icmp(#{saddr => {10,0,0,1}}, #{type => echo_request}),
    {accept, _, _} = nft_vm:eval_rule(nft_rules:protocol_accept(icmp), Pkt, new()).

test_nft_rules_set_lookup_drop(_) ->
    Pkt = nft_vm_pkt:with_sets(
        nft_vm_pkt:tcp(#{saddr => {10,0,0,5}}, #{dport => 80}),
        #{<<"blocklist">> => [<<10,0,0,5>>]}),
    {drop, _, _} = nft_vm:eval_rule(nft_rules:set_lookup_drop(<<"blocklist">>), Pkt, new()).

test_nft_rules_set_lookup_miss(_) ->
    Pkt = nft_vm_pkt:with_sets(
        nft_vm_pkt:tcp(#{saddr => {10,0,0,99}}, #{dport => 80}),
        #{<<"blocklist">> => [<<10,0,0,5>>]}),
    {break, _, _} = nft_vm:eval_rule(nft_rules:set_lookup_drop(<<"blocklist">>), Pkt, new()).

test_nft_rules_log_drop(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 9999}),
    {drop, _, _} = nft_vm:eval_rule(nft_rules:log_drop(<<"DROP: ">>), Pkt, new()).

%% ===================================================================
%% Full Chain Simulation
%% ===================================================================

test_chain_erlkoenig_firewall(_) ->
    Bl = [<<10,0,0,5>>, <<10,0,0,6>>],
    Rules = [
        nft_rules:ct_established_accept(),
        nft_rules:iif_accept(),
        nft_rules:set_lookup_drop(<<"blocklist">>),
        nft_rules:tcp_accept(22),
        nft_rules:tcp_accept(80),
        nft_rules:tcp_accept(443),
        nft_rules:protocol_accept(icmp),
        nft_rules:log_drop(<<"DROP: ">>)
    ],
    S = fun(P) -> nft_vm_pkt:with_sets(P, #{<<"blocklist">> => Bl}) end,

    {accept, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {192,168,1,1}}, #{dport => 22}))),
    {accept, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {192,168,1,1}}, #{dport => 80}))),
    {accept, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {192,168,1,1}}, #{dport => 443}))),
    {accept, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:icmp(#{saddr => {192,168,1,1}}, #{type => echo_request}))),
    {accept, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {192,168,1,1}}, #{dport => 9999, flags => ack}))),
    {accept, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {127,0,0,1}}, #{dport => 9999}, #{iif => 1}))),
    {drop, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {10,0,0,5}}, #{dport => 80}))),
    {drop, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {192,168,1,1}}, #{dport => 9999}))),
    {drop, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:udp(#{saddr => {192,168,1,1}}, #{dport => 5000}))).

test_chain_ssh_bruteforce(_) ->
    [Drop, Accept] = nft_rules:tcp_accept_limited(
        22, <<"ssh">>, #{rate => 25, burst => 5}),
    Rules = [
        nft_rules:ct_established_accept(),
        Drop, Accept,
        nft_rules:log_drop(<<"DROP: ">>)
    ],
    Ssh = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    {accept, _} = nft_vm:eval_chain(Rules,
        nft_vm_pkt:with_limit_state(Ssh, #{default => false})),
    {drop, _} = nft_vm:eval_chain(Rules,
        nft_vm_pkt:with_limit_state(Ssh, #{default => true})).

test_chain_default_policy(_) ->
    Rules = [nft_rules:tcp_accept(22)],
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 9999}),
    {drop, _} = nft_vm:eval_chain(Rules, Pkt, drop),
    {accept, _} = nft_vm:eval_chain(Rules, Pkt, accept).

test_chain_first_match_wins(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    Rules = [nft_rules:tcp_accept(22), nft_rules:log_drop(<<"DROP: ">>)],
    {accept, _} = nft_vm:eval_chain(Rules, Pkt).

%% ===================================================================
%% IPv6 Tests
%% ===================================================================

test_ipv6_nfproto(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}}, #{dport => 80}),
    {ok, R} = nft_vm:eval_expr({meta, #{key => nfproto, dreg => 1}}, Pkt, new()),
    ?assertEqual(<<10>>, reg(1, R)).

test_ipv6_set_lookup_drop(_) ->
    V6Addr = <<16#2001:16, 16#0db8:16, 0:80, 5:16>>,
    Pkt = nft_vm_pkt:with_sets(
        nft_vm_pkt:tcp(#{saddr => {16#2001, 16#db8, 0, 0, 0, 0, 0, 5}}, #{dport => 80}),
        #{<<"blocklist6">> => [V6Addr]}),
    Rule = nft_rules:set_lookup_drop(<<"blocklist6">>, ipv6_addr),
    {drop, _, _} = nft_vm:eval_rule(Rule, Pkt, new()).

test_ipv6_dual_stack_chain(_) ->
    V4Blocked = <<10,0,0,5>>,
    V6Blocked = <<16#2001:16, 16#0db8:16, 0:80, 6:16>>,

    Rules = [
        nft_rules:ct_established_accept(),
        nft_rules:set_lookup_drop(<<"blocklist">>, ipv4_addr),
        nft_rules:set_lookup_drop(<<"blocklist6">>, ipv6_addr),
        nft_rules:tcp_accept(22),
        nft_rules:tcp_accept(80),
        nft_rules:log_drop(<<"DROP: ">>)
    ],

    S = fun(P) ->
        nft_vm_pkt:with_sets(P, #{
            <<"blocklist">> => [V4Blocked],
            <<"blocklist6">> => [V6Blocked]
        })
    end,

    %% IPv4 allowed traffic
    {accept, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {192,168,1,1}}, #{dport => 22}))),

    %% IPv4 blocked traffic
    {drop, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {10,0,0,5}}, #{dport => 80}))),

    %% IPv6 allowed traffic on port 80
    {accept, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}}, #{dport => 80}))),

    %% IPv6 blocked traffic
    {drop, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {16#2001, 16#db8, 0, 0, 0, 0, 0, 6}}, #{dport => 80}))),

    %% IPv6 unmatched port → default drop (log_drop)
    {drop, _} = nft_vm:eval_chain(Rules,
        S(nft_vm_pkt:tcp(#{saddr => {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}}, #{dport => 9999}))).

%% ===================================================================
%% IR Compatibility
%% ===================================================================

test_ir_produces_vm_terms(_) ->
    Rule = [
        nft_expr_ir:meta(l4proto, 1),
        nft_expr_ir:cmp(eq, 1, <<6>>),
        nft_expr_ir:tcp_dport(1),
        nft_expr_ir:cmp(eq, 1, <<22:16/big>>),
        nft_expr_ir:accept()
    ],
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    {accept, _, _} = nft_vm:eval_rule(Rule, Pkt, new()),
    PktWrong = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80}),
    {break, _, _} = nft_vm:eval_rule(Rule, PktWrong, new()).

test_ir_nat_tuple(_) ->
    ?assertMatch({nat, #{type := snat}}, nft_expr_ir:snat(1, 2)),
    ?assertMatch({nat, #{type := dnat}}, nft_expr_ir:dnat(1, 2)),
    ?assertMatch({masq, #{}}, nft_expr_ir:masq()).

test_ir_generic_tuple(_) ->
    ?assertMatch({osf, #{dreg := 1}}, nft_expr_ir:generic(osf, #{dreg => 1})),
    ?assertMatch({fib, #{result := 0}},
        nft_expr_ir:generic(fib, #{result => 0, flags => 3, dreg => 1})).

%% ===================================================================
%% Trace
%% ===================================================================

test_trace_printing(_) ->
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    {accept, Trace} = nft_vm:eval_chain([nft_rules:tcp_accept(22)], Pkt),
    ?assertEqual(5, length(Trace)),
    #{expr := {meta, _}} = hd(Trace),
    #{expr := {immediate, #{verdict := accept}}} = lists:last(Trace),
    nft_vm:print_trace(Trace).

%% ===================================================================
%% WireGuard SPA Tests
%% ===================================================================

test_wg_blocked_without_auth(_) ->
    %% UDP 51820 should be dropped if source IP is NOT in allowlist
    Rules = wg_chain(),
    Pkt = wg_pkt(#{saddr => {10,0,0,5}}, 51820),
    {drop, _} = nft_vm:eval_chain(Rules, Pkt).

test_wg_allowed_with_auth(_) ->
    %% UDP 51820 should be accepted if source IP IS in allowlist
    Rules = wg_chain(),
    Pkt = nft_vm_pkt:with_sets(
        wg_pkt(#{saddr => {10,0,0,5}}, 51820),
        #{<<"wg_allow">> => [<<10,0,0,5>>]}),
    {accept, _} = nft_vm:eval_chain(Rules, Pkt).

test_wg_spa_captured(_) ->
    %% UDP 61820 (SPA port) should be dropped (after NFLOG capture)
    Rules = wg_chain(),
    Pkt = wg_pkt(#{saddr => {10,0,0,5}}, 61820),
    {drop, _} = nft_vm:eval_chain(Rules, Pkt).

test_wg_established_continues(_) ->
    %% An established connection should pass through
    %% even without being in the allowlist (ct_established_accept matches)
    Rules = wg_chain(),
    Pkt = nft_vm_pkt:udp(#{saddr => {10,0,0,5}}, #{dport => 51820},
                          #{ct_state => established}),
    {accept, _} = nft_vm:eval_chain(Rules, Pkt).

%% Build the WG firewall chain for testing
wg_chain() ->
    [
        nft_rules:ct_established_accept(),
        nft_rules:iif_accept(),
        nft_rules:nflog_capture_udp(61820, <<"SPA:">>, 3),
        nft_rules:set_lookup_udp_accept(<<"wg_allow">>, 51820, ipv4_addr),
        nft_rules:set_lookup_udp_accept(<<"wg_allow6">>, 51820, ipv6_addr),
        nft_rules:tcp_accept(22),
        nft_rules:log_drop(<<"DROP: ">>)
    ].

wg_pkt(IpOpts, Port) ->
    nft_vm_pkt:udp(IpOpts, #{dport => Port}).

%% ===================================================================
%% Helpers
%% ===================================================================

new() -> nft_vm:new_regs().
with_reg(Reg, Val) -> #{verdict => continue, data => #{Reg => Val}}.
reg(Reg, #{data := Data}) -> maps:get(Reg, Data, <<0:32>>).
