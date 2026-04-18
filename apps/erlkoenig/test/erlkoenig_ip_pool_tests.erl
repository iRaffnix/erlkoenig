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
    application:set_env(erlkoenig, subnet, {10, 99, 0, 0}),
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

%% =================================================================
%% Non-/24 prefixes — pool sizes itself based on netmask
%% =================================================================

prefix_test_() ->
    [
     {"prefix /28 yields 13 host addresses",  fun prefix_28_size/0},
     {"prefix /28 last address is .14",       fun prefix_28_last/0},
     {"prefix /16 supports 65 533 addresses", fun prefix_16_capacity/0},
     {"prefix /30 yields exactly one host",   fun prefix_30_one_host/0},
     {"prefix /31 is rejected at boot",       fun prefix_31_rejected/0},
     {"release outside pool range is no-op",  fun release_out_of_range/0}
    ].

prefix_28_size() ->
    %% 10.99.0.16/28: network=.16, gateway=.17, hosts=.18..30, bcast=.31
    %% pool capacity = 13 (.18 through .30)
    Pid = start_zone(strat28, {10, 99, 0, 16}, 28),
    try
        Allocated = collect_until_exhausted(Pid),
        ?assertEqual(13, length(Allocated)),
        ?assertEqual({10, 99, 0, 18}, hd(Allocated)),
        ?assertEqual({10, 99, 0, 30}, lists:last(Allocated))
    after stop_zone(Pid)
    end.

prefix_28_last() ->
    Pid = start_zone(strat28b, {10, 99, 0, 16}, 28),
    try
        _ = [gen_server:call(Pid, allocate) || _ <- lists:seq(1, 12)],
        ?assertEqual({ok, {10, 99, 0, 30}}, gen_server:call(Pid, allocate)),
        ?assertEqual({error, exhausted},   gen_server:call(Pid, allocate))
    after stop_zone(Pid)
    end.

prefix_16_capacity() ->
    %% /16 has 2^16 - 3 = 65533 host addresses (network, gateway, broadcast all skipped)
    Pid = start_zone(strat16, {10, 99, 0, 0}, 16),
    try
        First = gen_server:call(Pid, allocate),
        ?assertEqual({ok, {10, 99, 0, 2}}, First),
        %% Walking 65 533 allocations is slow but not slow enough to skip;
        %% bound to ~250 ms on a normal machine.
        Rest = [gen_server:call(Pid, allocate) || _ <- lists:seq(1, 65532)],
        ?assertMatch({ok, {10, 99, 255, 254}}, lists:last(Rest)),
        ?assertEqual({error, exhausted}, gen_server:call(Pid, allocate))
    after stop_zone(Pid)
    end.

prefix_30_one_host() ->
    %% 10.99.0.0/30: network=.0, gateway=.1, host=.2, bcast=.3 → exactly 1 host
    Pid = start_zone(strat30, {10, 99, 0, 0}, 30),
    try
        ?assertEqual({ok, {10, 99, 0, 2}}, gen_server:call(Pid, allocate)),
        ?assertEqual({error, exhausted},   gen_server:call(Pid, allocate))
    after stop_zone(Pid)
    end.

prefix_31_rejected() ->
    %% /31 leaves no room for gateway + host. Pool refuses to start.
    process_flag(trap_exit, true),
    Result = (catch erlkoenig_ip_pool:start_link(
                      #{zone => strat31,
                        network => #{subnet => {10, 99, 0, 0}, netmask => 31}})),
    ?assertMatch({error, {unsupported_netmask, 31, _, _}}, Result).

release_out_of_range() ->
    %% Releasing an address outside the pool's window must not corrupt
    %% the free list — this guards against operator/test typos.
    Pid = start_zone(stratrr, {10, 99, 0, 0}, 28),
    try
        gen_server:cast(Pid, {release, {99, 99, 99, 99}}),
        timer:sleep(10),
        %% First allocate should still be the natural .2, not .99.99.99.99
        ?assertEqual({ok, {10, 99, 0, 2}}, gen_server:call(Pid, allocate))
    after stop_zone(Pid)
    end.

start_zone(Name, Subnet, Netmask) ->
    {ok, Pid} = erlkoenig_ip_pool:start_link(
                  #{zone => Name,
                    network => #{subnet => Subnet, netmask => Netmask}}),
    Pid.

stop_zone(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    MRef = monitor(process, Pid),
    receive {'DOWN', MRef, process, Pid, _} -> ok
    after 1000 -> ok
    end.

collect_until_exhausted(Pid) ->
    case gen_server:call(Pid, allocate) of
        {ok, Ip}            -> [Ip | collect_until_exhausted(Pid)];
        {error, exhausted}  -> []
    end.
