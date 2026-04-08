%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_threat_mesh_tests).
-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% Test Setup
%% ===================================================================

setup() ->
    %% Start pg scope
    case pg:start_link(erlkoenig_nft) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end,
    %% Mock erlkoenig_nft:ban/unban — just track calls
    put(ban_calls, []),
    put(unban_calls, []),
    ok.

start_mesh() ->
    start_mesh(#{}).

start_mesh(Config) ->
    %% Stop existing mesh if running (from previous test / actor tests)
    case whereis(erlkoenig_threat_mesh) of
        undefined -> ok;
        OldPid -> gen_server:stop(OldPid), timer:sleep(10)
    end,
    {ok, Pid} = erlkoenig_threat_mesh:start_link(Config),
    Pid.

stop_mesh(Pid) ->
    gen_server:stop(Pid).

%% ===================================================================
%% Tests
%% ===================================================================

mesh_starts_test() ->
    setup(),
    Pid = start_mesh(),
    ?assert(is_process_alive(Pid)),
    stop_mesh(Pid).

local_ban_records_source_test() ->
    setup(),
    Pid = start_mesh(),
    IP = <<1,2,3,4>>,
    BanUntil = os:system_time(millisecond) + 60000,
    erlkoenig_threat_mesh:local_ban(IP, BanUntil, honeypot),
    timer:sleep(50),
    Bans = erlkoenig_threat_mesh:active_bans(),
    ?assert(maps:is_key(IP, Bans)),
    Sources = maps:get(IP, Bans),
    ?assert(maps:is_key(node(), Sources)),
    stop_mesh(Pid).

local_unban_removes_source_test() ->
    setup(),
    Pid = start_mesh(),
    IP = <<5,6,7,8>>,
    BanUntil = os:system_time(millisecond) + 60000,
    erlkoenig_threat_mesh:local_ban(IP, BanUntil, flood),
    timer:sleep(50),
    erlkoenig_threat_mesh:local_unban(IP),
    timer:sleep(50),
    Bans = erlkoenig_threat_mesh:active_bans(),
    ?assertNot(maps:is_key(IP, Bans)),
    stop_mesh(Pid).

whitelist_prevents_ban_test() ->
    setup(),
    Pid = start_mesh(#{whitelist => [{127,0,0,1}]}),
    %% Normalize the whitelisted IP the same way the mesh does
    {ok, WlIP} = erlkoenig_nft_ip:normalize({127,0,0,1}),
    BanUntil = os:system_time(millisecond) + 60000,
    erlkoenig_threat_mesh:local_ban(WlIP, BanUntil, honeypot),
    timer:sleep(50),
    Bans = erlkoenig_threat_mesh:active_bans(),
    ?assertNot(maps:is_key(WlIP, Bans)),
    stop_mesh(Pid).

remote_ban_merges_test() ->
    setup(),
    Pid = start_mesh(),
    IP = <<9,10,11,12>>,
    %% Simulate remote ban (direct message, as if from pg)
    BanUntil = os:system_time(millisecond) + 120000,
    Pid ! {ban, IP, BanUntil, port_scan, 'remote@node'},
    timer:sleep(50),
    Bans = erlkoenig_threat_mesh:active_bans(),
    Sources = maps:get(IP, Bans),
    ?assert(maps:is_key('remote@node', Sources)),
    stop_mesh(Pid).

max_expiry_merge_test() ->
    setup(),
    Pid = start_mesh(),
    IP = <<13,14,15,16>>,
    Now = os:system_time(millisecond),
    %% Local ban until Now + 60s
    erlkoenig_threat_mesh:local_ban(IP, Now + 60000, flood),
    timer:sleep(20),
    %% Remote ban until Now + 120s (longer)
    Pid ! {ban, IP, Now + 120000, port_scan, 'remote@node'},
    timer:sleep(50),
    Bans = erlkoenig_threat_mesh:active_bans(),
    Sources = maps:get(IP, Bans),
    %% Both sources present
    ?assert(maps:is_key(node(), Sources)),
    ?assert(maps:is_key('remote@node', Sources)),
    %% Remote expiry is higher
    ?assert(maps:get('remote@node', Sources) > maps:get(node(), Sources)),
    stop_mesh(Pid).

local_unban_keeps_remote_ban_test() ->
    setup(),
    Pid = start_mesh(),
    IP = <<17,18,19,20>>,
    Now = os:system_time(millisecond),
    %% Local ban
    erlkoenig_threat_mesh:local_ban(IP, Now + 60000, flood),
    timer:sleep(20),
    %% Remote ban (longer)
    Pid ! {ban, IP, Now + 120000, port_scan, 'remote@node'},
    timer:sleep(20),
    %% Local unban
    erlkoenig_threat_mesh:local_unban(IP),
    timer:sleep(50),
    %% IP should still be in active_bans (remote source active)
    Bans = erlkoenig_threat_mesh:active_bans(),
    ?assert(maps:is_key(IP, Bans)),
    Sources = maps:get(IP, Bans),
    ?assertNot(maps:is_key(node(), Sources)),
    ?assert(maps:is_key('remote@node', Sources)),
    stop_mesh(Pid).

idempotent_ban_test() ->
    setup(),
    Pid = start_mesh(),
    IP = <<21,22,23,24>>,
    BanUntil = os:system_time(millisecond) + 60000,
    erlkoenig_threat_mesh:local_ban(IP, BanUntil, flood),
    timer:sleep(20),
    %% Same ban again — should not crash or duplicate
    erlkoenig_threat_mesh:local_ban(IP, BanUntil, flood),
    timer:sleep(50),
    Bans = erlkoenig_threat_mesh:active_bans(),
    ?assert(maps:is_key(IP, Bans)),
    stop_mesh(Pid).
