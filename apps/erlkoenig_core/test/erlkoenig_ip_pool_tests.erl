%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_ip_pool (IP address allocation).
%%%
%%% Tests the gen_server logic: sequential allocation, exhaustion,
%%% release/reuse, double-release safety, and used_count accuracy.
%%%
%%% Each test starts its own ip_pool gen_server with a test subnet
%%% and stops it on cleanup. No root or network required.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_ip_pool_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% =================================================================
%% Test generator with setup/teardown
%% =================================================================

ip_pool_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun allocate_first_ip/1,
      fun allocate_sequential/1,
      fun allocate_exhausted/1,
      fun release_and_reuse/1,
      fun double_release_no_duplicate/1,
      fun used_count_initial/1,
      fun used_count_after_alloc/1,
      fun used_count_after_release/1
     ]}.

setup() ->
    %% Set subnet in app env so init(legacy) picks it up
    application:set_env(erlkoenig_core, subnet, {10, 99, 0, 0}),
    {ok, Pid} = erlkoenig_ip_pool:start_link(),
    Pid.

cleanup(Pid) ->
    %% Unlink first to avoid crash propagation in test
    unlink(Pid),
    exit(Pid, shutdown),
    %% Wait for process to actually terminate
    MRef = monitor(process, Pid),
    receive {'DOWN', MRef, process, Pid, _} -> ok
    after 1000 -> ok
    end,
    %% Unregister if still registered (cleanup for next test)
    try unregister(erlkoenig_ip_pool) catch _:_ -> ok end.

%% =================================================================
%% Allocation
%% =================================================================

allocate_first_ip(_Pid) ->
    %% First IP must be .2 (.1 is the gateway)
    ?_assertEqual({ok, {10, 99, 0, 2}}, erlkoenig_ip_pool:allocate()).

allocate_sequential(_Pid) ->
    %% IPs are handed out sequentially: .2, .3, .4
    {ok, Ip1} = erlkoenig_ip_pool:allocate(),
    {ok, Ip2} = erlkoenig_ip_pool:allocate(),
    {ok, Ip3} = erlkoenig_ip_pool:allocate(),
    [
     ?_assertEqual({10, 99, 0, 2}, Ip1),
     ?_assertEqual({10, 99, 0, 3}, Ip2),
     ?_assertEqual({10, 99, 0, 4}, Ip3)
    ].

allocate_exhausted(_Pid) ->
    %% Exhaust the pool: .2 through .254 = 253 addresses
    lists:foreach(fun(_) -> erlkoenig_ip_pool:allocate() end,
                  lists:seq(1, 253)),
    ?_assertEqual({error, exhausted}, erlkoenig_ip_pool:allocate()).

%% =================================================================
%% Release and reuse
%% =================================================================

release_and_reuse(_Pid) ->
    %% Allocate, release, allocate again -> same IP
    {ok, Ip} = erlkoenig_ip_pool:allocate(),
    erlkoenig_ip_pool:release(Ip),
    %% Small delay for async cast to be processed
    timer:sleep(10),
    ?_assertEqual({ok, Ip}, erlkoenig_ip_pool:allocate()).

double_release_no_duplicate(_Pid) ->
    %% Double release must not create duplicate in free list
    {ok, Ip} = erlkoenig_ip_pool:allocate(),
    erlkoenig_ip_pool:release(Ip),
    erlkoenig_ip_pool:release(Ip),
    timer:sleep(10),
    {ok, Ip1} = erlkoenig_ip_pool:allocate(),
    {ok, Ip2} = erlkoenig_ip_pool:allocate(),
    %% Ip1 should be the released IP, Ip2 should be a fresh one
    [
     ?_assertEqual(Ip, Ip1),
     ?_assertEqual({10, 99, 0, 3}, Ip2)
    ].

%% =================================================================
%% used_count
%% =================================================================

used_count_initial(_Pid) ->
    ?_assertEqual(0, erlkoenig_ip_pool:used_count()).

used_count_after_alloc(_Pid) ->
    {ok, _} = erlkoenig_ip_pool:allocate(),
    {ok, _} = erlkoenig_ip_pool:allocate(),
    {ok, _} = erlkoenig_ip_pool:allocate(),
    ?_assertEqual(3, erlkoenig_ip_pool:used_count()).

used_count_after_release(_Pid) ->
    {ok, Ip1} = erlkoenig_ip_pool:allocate(),
    {ok, _Ip2} = erlkoenig_ip_pool:allocate(),
    {ok, _Ip3} = erlkoenig_ip_pool:allocate(),
    erlkoenig_ip_pool:release(Ip1),
    timer:sleep(10),
    ?_assertEqual(2, erlkoenig_ip_pool:used_count()).
