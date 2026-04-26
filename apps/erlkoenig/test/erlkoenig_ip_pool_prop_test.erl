%%%-------------------------------------------------------------------
%%% @doc Property tests for erlkoenig_ip_pool state invariants.
%%%
%%% These tests focus on release messages that arrive before an IP was
%%% ever handed out. In production that can happen through stale async
%%% cleanup, retries, or misrouted zone release calls. Such messages
%%% must not seed the free list or change future allocation order.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_ip_pool_prop_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(SUBNET, {10, 99, 42, 0}).
-define(NETMASK, 28).
-define(FIRST_HOST, 2).
-define(LAST_HOST, 14).
-define(COOLDOWN_WAIT_MS, 650).

pre_release_never_allocated_test_() ->
    {timeout, 30, fun() ->
        ?assert(proper:quickcheck(
                  prop_pre_release_never_allocated_noop(),
                  [{numtests, 20}, {to_file, user}]))
    end}.

prop_pre_release_never_allocated_noop() ->
    ?FORALL(LastOctets,
            proper_types:list(proper_types:choose(?FIRST_HOST, ?LAST_HOST)),
        begin
            Pid = start_pool(),
            try
                lists:foreach(
                  fun(D) ->
                      gen_server:cast(Pid, {release, {10, 99, 42, D}})
                  end,
                  LastOctets),
                timer:sleep(?COOLDOWN_WAIT_MS),
                Allocated = collect_until_exhausted(Pid),
                Expected = [{10, 99, 42, D}
                            || D <- lists:seq(?FIRST_HOST, ?LAST_HOST)],
                Allocated =:= Expected
                    andalso length(Allocated) =:= length(lists:usort(Allocated))
            after
                stop_pool(Pid)
            end
        end).

start_pool() ->
    Zone = list_to_atom("ip_pool_prop_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, Pid} = erlkoenig_ip_pool:start_link(
                  #{zone => Zone,
                    network => #{subnet => ?SUBNET, netmask => ?NETMASK}}),
    Pid.

stop_pool(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    MRef = monitor(process, Pid),
    receive
        {'DOWN', MRef, process, Pid, _} -> ok
    after 1000 ->
        ok
    end.

collect_until_exhausted(Pid) ->
    case gen_server:call(Pid, allocate) of
        {ok, Ip} -> [Ip | collect_until_exhausted(Pid)];
        {error, exhausted} -> []
    end.
