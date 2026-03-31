%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_zone (zone registry).
%%%
%%% Tests zone loading from app env, default zone fallback,
%%% normalize_config defaults, service registration and lookup.
%%%
%%% Each test starts its own zone gen_server and stops it on cleanup.
%%% No root or network required.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_zone_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% =================================================================
%% Default zone (legacy config)
%% =================================================================

default_zone_test_() ->
    {setup,
     fun setup_legacy/0,
     fun cleanup/1,
     fun(_Pid) -> [
        ?_assertEqual(default, erlkoenig_zone:default_zone()),
        ?_assertEqual([default], erlkoenig_zone:zones()),
        ?_assertMatch(#{bridge  := <<"erlkoenig_br0">>,
                        subnet  := {10, 0, 0, 0},
                        gateway := {10, 0, 0, 1},
                        netmask := 24,
                        policy  := allow_outbound},
                      erlkoenig_zone:zone_config(default))
     ] end}.

%% =================================================================
%% Multi-zone config
%% =================================================================

multi_zone_test_() ->
    {setup,
     fun setup_multi/0,
     fun cleanup/1,
     fun(_Pid) -> [
        fun() ->
            Zones = lists:sort(erlkoenig_zone:zones()),
            ?assertEqual([default, dmz], Zones)
        end,
        fun() ->
            Cfg = erlkoenig_zone:zone_config(dmz),
            ?assertEqual(<<"erlkoenig_dmz">>, maps:get(bridge, Cfg)),
            ?assertEqual({172, 16, 0, 0}, maps:get(subnet, Cfg))
        end
     ] end}.

%% =================================================================
%% zone_config for unknown zone
%% =================================================================

unknown_zone_test_() ->
    {setup,
     fun setup_legacy/0,
     fun cleanup/1,
     fun(_Pid) -> [
        ?_assertError({unknown_zone, nonexistent},
                      erlkoenig_zone:zone_config(nonexistent))
     ] end}.

%% =================================================================
%% Service registration and lookup
%% =================================================================

register_and_lookup_service_test_() ->
    {setup,
     fun setup_legacy/0,
     fun cleanup/1,
     fun(_Pid) -> [
        fun() ->
            %% Register self() as bridge service for default zone
            ok = erlkoenig_zone:register_service(default, bridge, self()),
            ?assertEqual(self(), erlkoenig_zone:bridge(default))
        end
     ] end}.

service_not_registered_test_() ->
    {setup,
     fun setup_legacy/0,
     fun cleanup/1,
     fun(_Pid) -> [
        %% Looking up unregistered service must crash (assertive style)
        ?_assertError({zone_service_not_registered, default, bridge},
                      erlkoenig_zone:bridge(default))
     ] end}.

register_unknown_zone_test_() ->
    {setup,
     fun setup_legacy/0,
     fun cleanup/1,
     fun(_Pid) -> [
        ?_assertEqual({error, unknown_zone},
                      erlkoenig_zone:register_service(nonexistent, bridge, self()))
     ] end}.

%% =================================================================
%% normalize_config (tested through zone loading)
%% =================================================================

normalize_fills_defaults_test_() ->
    %% A zone defined with minimal config should get all defaults
    {setup,
     fun() ->
         application:set_env(erlkoenig, zones,
             [{minimal, #{}}]),
         cleanup_zone_ets(),
         {ok, Pid} = erlkoenig_zone:start_link(),
         Pid
     end,
     fun cleanup/1,
     fun(_Pid) -> [
        fun() ->
            Cfg = erlkoenig_zone:zone_config(minimal),
            ?assertEqual(<<"erlkoenig_br0">>, maps:get(bridge, Cfg)),
            ?assertEqual({10, 0, 0, 0}, maps:get(subnet, Cfg)),
            ?assertEqual({10, 0, 0, 1}, maps:get(gateway, Cfg)),
            ?assertEqual(24, maps:get(netmask, Cfg)),
            ?assertEqual(allow_outbound, maps:get(policy, Cfg))
        end
     ] end}.

normalize_override_test_() ->
    %% Partial overrides: specified keys override, rest uses defaults
    {setup,
     fun() ->
         application:set_env(erlkoenig, zones,
             [{custom, #{bridge => <<"my_br">>, netmask => 16}}]),
         cleanup_zone_ets(),
         {ok, Pid} = erlkoenig_zone:start_link(),
         Pid
     end,
     fun cleanup/1,
     fun(_Pid) -> [
        fun() ->
            Cfg = erlkoenig_zone:zone_config(custom),
            ?assertEqual(<<"my_br">>, maps:get(bridge, Cfg)),
            ?assertEqual(16, maps:get(netmask, Cfg)),
            %% Rest should be defaults
            ?assertEqual({10, 0, 0, 0}, maps:get(subnet, Cfg)),
            ?assertEqual({10, 0, 0, 1}, maps:get(gateway, Cfg))
        end
     ] end}.

%% =================================================================
%% Setup / Cleanup
%% =================================================================

setup_legacy() ->
    %% Remove zones key so it falls back to legacy single zone
    application:unset_env(erlkoenig, zones),
    %% Reset legacy keys to defaults (may be polluted by other tests)
    application:set_env(erlkoenig, subnet, {10, 0, 0, 0}),
    application:set_env(erlkoenig, gateway, {10, 0, 0, 1}),
    application:set_env(erlkoenig, bridge_name, <<"erlkoenig_br0">>),
    application:set_env(erlkoenig, netmask, 24),
    cleanup_zone_ets(),
    {ok, Pid} = erlkoenig_zone:start_link(),
    Pid.

setup_multi() ->
    application:set_env(erlkoenig, zones, [
        {default, #{bridge => <<"erlkoenig_br0">>,
                    subnet => {10, 0, 0, 0},
                    gateway => {10, 0, 0, 1},
                    netmask => 24,
                    policy => allow_outbound}},
        {dmz, #{bridge => <<"erlkoenig_dmz">>,
                subnet => {172, 16, 0, 0},
                gateway => {172, 16, 0, 1},
                netmask => 24,
                policy => isolate}}
    ]),
    cleanup_zone_ets(),
    {ok, Pid} = erlkoenig_zone:start_link(),
    Pid.

cleanup(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    MRef = monitor(process, Pid),
    receive {'DOWN', MRef, process, Pid, _} -> ok
    after 1000 -> ok
    end,
    try unregister(erlkoenig_zone) catch _:_ -> ok end,
    cleanup_zone_ets().

cleanup_zone_ets() ->
    %% Delete the ETS table if it exists from a previous test
    case ets:whereis(erlkoenig_zones) of
        undefined -> ok;
        _ ->
            try ets:delete(erlkoenig_zones)
            catch _:_ -> ok
            end
    end.
