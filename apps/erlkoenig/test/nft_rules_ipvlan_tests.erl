%%%-------------------------------------------------------------------
%%% @doc Tests for IPVLAN-specific nft_rules: ip_saddr_jump, ip_daddr_jump.
%%%
%%% These rule builders return IR expression lists. We verify structure
%%% (correct expressions in correct order) without encoding to netlink.
%%% @end
%%%-------------------------------------------------------------------

-module(nft_rules_ipvlan_tests).

-include_lib("eunit/include/eunit.hrl").

%% =================================================================
%% ip_saddr_jump/2
%% =================================================================

ip_saddr_jump_returns_three_exprs_test() ->
    Rule = nft_rules:ip_saddr_jump(<<10, 50, 100, 2>>, <<"ct_web_0">>),
    ?assertEqual(3, length(Rule)).

ip_saddr_jump_starts_with_payload_test() ->
    [First | _] = nft_rules:ip_saddr_jump(<<10, 0, 0, 1>>, <<"chain">>),
    ?assertMatch({payload, _}, First).

ip_saddr_jump_has_cmp_test() ->
    [_, Second | _] = nft_rules:ip_saddr_jump(<<10, 0, 0, 1>>, <<"chain">>),
    ?assertMatch({cmp, _}, Second).

ip_saddr_jump_ends_with_jump_test() ->
    Rule = nft_rules:ip_saddr_jump(<<10, 0, 0, 1>>, <<"ct_web_0">>),
    Last = lists:last(Rule),
    ?assertMatch({immediate, #{verdict := {jump, <<"ct_web_0">>}}}, Last).

ip_saddr_jump_cmp_contains_ip_test() ->
    [_, {cmp, #{data := Data}} | _] =
        nft_rules:ip_saddr_jump(<<192, 168, 1, 42>>, <<"chain">>),
    ?assertEqual(<<192, 168, 1, 42>>, Data).

%% =================================================================
%% ip_daddr_jump/2
%% =================================================================

ip_daddr_jump_returns_three_exprs_test() ->
    Rule = nft_rules:ip_daddr_jump(<<10, 50, 100, 5>>, <<"ct_app_0">>),
    ?assertEqual(3, length(Rule)).

ip_daddr_jump_ends_with_jump_test() ->
    Rule = nft_rules:ip_daddr_jump(<<10, 50, 100, 5>>, <<"ct_app_0">>),
    Last = lists:last(Rule),
    ?assertMatch({immediate, #{verdict := {jump, <<"ct_app_0">>}}}, Last).

ip_daddr_jump_cmp_contains_ip_test() ->
    [_, {cmp, #{data := Data}} | _] =
        nft_rules:ip_daddr_jump(<<172, 16, 0, 1>>, <<"chain">>),
    ?assertEqual(<<172, 16, 0, 1>>, Data).

%% =================================================================
%% Structural difference: saddr vs daddr
%% =================================================================

saddr_and_daddr_differ_in_payload_test() ->
    Ip = <<10, 0, 0, 1>>,
    [{payload, SaddrPayload} | _] = nft_rules:ip_saddr_jump(Ip, <<"c">>),
    [{payload, DaddrPayload} | _] = nft_rules:ip_daddr_jump(Ip, <<"c">>),
    %% saddr offset=12, daddr offset=16 (IPv4 header)
    ?assertNotEqual(SaddrPayload, DaddrPayload).
