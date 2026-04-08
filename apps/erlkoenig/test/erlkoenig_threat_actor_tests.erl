%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_threat_actor_tests).
-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% Test Setup — start pg + real threat_mesh
%% ===================================================================

setup() ->
    Reg = erlkoenig_threat_actor_test_reg,
    case ets:whereis(Reg) of
        undefined -> ets:new(Reg, [named_table, set, public, {read_concurrency, true}]);
        _ -> Reg
    end,
    case pg:start_link(erlkoenig_nft) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end,
    %% Start real threat_mesh if not already running
    case whereis(erlkoenig_threat_mesh) of
        undefined ->
            {ok, _} = erlkoenig_threat_mesh:start_link(#{});
        _ ->
            ok
    end,
    Reg.

teardown(Reg) ->
    try ets:delete(Reg) catch error:badarg -> ok end,
    ok.

base_config(Reg) ->
    #{flood_max => 5, flood_window => 10,
      scan_max => 20, scan_window => 60,
      slow_max => 5, slow_window => 3600,
      ban_duration => 60,
      honeypot_ban_duration => 300,
      honeypot_ports => sets:from_list([22, 23], [{version, 2}]),
      registry => Reg}.

start_actor(IP, Reg) ->
    Config = base_config(Reg),
    {ok, Pid} = erlkoenig_threat_actor:start_link(IP, Config),
    Pid.

%% ===================================================================
%% Tests
%% ===================================================================

actor_starts_in_observing_test() ->
    Reg = setup(),
    Pid = start_actor(<<1,2,3,4>>, Reg),
    ?assert(is_process_alive(Pid)),
    State = get_statem_state(Pid),
    ?assertEqual(observing, State),
    gen_statem:stop(Pid),
    teardown(Reg).

honeypot_triggers_banned_test() ->
    Reg = setup(),
    Pid = start_actor(<<10,0,0,1>>, Reg),
    erlkoenig_threat_actor:connection(Pid, 22),
    timer:sleep(50),
    ?assertEqual(banned, get_statem_state(Pid)),
    gen_statem:stop(Pid),
    teardown(Reg).

flood_triggers_banned_test() ->
    Reg = setup(),
    Pid = start_actor(<<10,0,0,2>>, Reg),
    %% 5 connections = flood_max → banned
    lists:foreach(fun(_) ->
        erlkoenig_threat_actor:connection(Pid, 80)
    end, lists:seq(1, 5)),
    timer:sleep(50),
    ?assertEqual(banned, get_statem_state(Pid)),
    gen_statem:stop(Pid),
    teardown(Reg).

normal_traffic_stays_observing_test() ->
    Reg = setup(),
    Pid = start_actor(<<10,0,0,4>>, Reg),
    erlkoenig_threat_actor:connection(Pid, 80),
    timer:sleep(50),
    ?assertEqual(observing, get_statem_state(Pid)),
    gen_statem:stop(Pid),
    teardown(Reg).

three_ports_becomes_suspicious_test() ->
    Reg = setup(),
    Pid = start_actor(<<10,0,0,5>>, Reg),
    erlkoenig_threat_actor:connection(Pid, 80),
    erlkoenig_threat_actor:connection(Pid, 443),
    erlkoenig_threat_actor:connection(Pid, 8080),
    timer:sleep(50),
    ?assertEqual(suspicious, get_statem_state(Pid)),
    gen_statem:stop(Pid),
    teardown(Reg).

terminate_cleans_registry_test() ->
    Reg = setup(),
    IP = <<10,0,0,6>>,
    ets:insert(Reg, {IP, starting}),
    Config = base_config(Reg),
    {ok, Pid} = erlkoenig_threat_actor:start_link(IP, Config),
    ets:update_element(Reg, IP, {2, Pid}),
    ?assertEqual([{IP, Pid}], ets:lookup(Reg, IP)),
    gen_statem:stop(Pid),
    timer:sleep(50),
    ?assertEqual([], ets:lookup(Reg, IP)),
    teardown(Reg).

banned_ignores_connections_test() ->
    Reg = setup(),
    Pid = start_actor(<<10,0,0,7>>, Reg),
    erlkoenig_threat_actor:connection(Pid, 22),  %% honeypot → banned
    timer:sleep(50),
    ?assertEqual(banned, get_statem_state(Pid)),
    %% More connections while banned — should stay banned, not crash
    erlkoenig_threat_actor:connection(Pid, 80),
    erlkoenig_threat_actor:connection(Pid, 443),
    timer:sleep(50),
    ?assertEqual(banned, get_statem_state(Pid)),
    ?assert(is_process_alive(Pid)),
    gen_statem:stop(Pid),
    teardown(Reg).

%% ===================================================================
%% Helpers
%% ===================================================================

get_statem_state(Pid) ->
    {status, _, _, Items} = sys:get_status(Pid),
    %% gen_statem status format:
    %% Items = [PDict, running, Parent, [], [Header, Data1, Data2]]
    %% Data2 = {data, [{"State", {StateName, StateData}}]}
    StatusItems = lists:last(Items),
    {data, StateKV} = lists:last(StatusItems),
    {"State", {StateName, _StateData}} = lists:keyfind("State", 1, StateKV),
    StateName.
