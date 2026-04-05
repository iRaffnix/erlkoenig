-module(ban_expiry_test).
-include_lib("eunit/include/eunit.hrl").

%% Unit tests for kernel-side ban expiry (SPEC-NFT-017)

%% --- ban_ip/4 produces a msg_fun with timeout ---

ban_ip_with_timeout_test() ->
    MsgFun = nft_rules:ban_ip(<<"test">>, <<"blocklist">>, <<10,0,0,5>>, 3600000),
    ?assert(is_function(MsgFun, 1)),
    Bin = MsgFun(1),
    ?assert(is_binary(Bin)),
    ?assert(byte_size(Bin) > 0).

%% --- ban_ip/3 still works (backward compat) ---

ban_ip_without_timeout_test() ->
    MsgFun = nft_rules:ban_ip(<<"test">>, <<"blocklist">>, <<10,0,0,5>>),
    ?assert(is_function(MsgFun, 1)),
    Bin = MsgFun(1),
    ?assert(is_binary(Bin)).

%% --- ban_ip/4 produces larger message (timeout attribute) ---

ban_ip_timeout_adds_bytes_test() ->
    MsgFun3 = nft_rules:ban_ip(<<"test">>, <<"bl">>, <<10,0,0,5>>),
    MsgFun4 = nft_rules:ban_ip(<<"test">>, <<"bl">>, <<10,0,0,5>>, 3600000),
    Bin3 = MsgFun3(1),
    Bin4 = MsgFun4(1),
    %% Timeout adds 12 bytes (NLA header 4 + u64 value 8)
    ?assert(byte_size(Bin4) > byte_size(Bin3)).

%% --- ban_ip/4 works with IPv6 ---

ban_ip_ipv6_timeout_test() ->
    IPv6 = <<32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1>>,  %% 2001:db8::1
    MsgFun = nft_rules:ban_ip(<<"test">>, <<"blocklist6">>, IPv6, 7200000),
    Bin = MsgFun(1),
    ?assert(is_binary(Bin)).

%% --- Config with ban_duration is parseable ---

config_ban_duration_present_test() ->
    %% The firewall.term config has ct_guard with ban_duration
    {ok, [Config]} = file:consult("etc/firewall.term"),
    CtGuard = maps:get(ct_guard, Config, #{}),
    BanDuration = maps:get(ban_duration, CtGuard, undefined),
    ?assertEqual(3600, BanDuration).

%% --- Config with timeout flags loads correctly ---

config_with_timeout_sets_test() ->
    {ok, ChainMap} = nft_vm_config:load("etc/firewall.term"),
    %% Should still load and produce chains
    ?assert(maps:is_key(<<"inbound">>, ChainMap)),
    ?assert(maps:is_key(<<"prerouting_ban">>, ChainMap)).
