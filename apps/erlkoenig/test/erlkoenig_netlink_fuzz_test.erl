%%%-------------------------------------------------------------------
%%% @doc erlkoenig_netlink parser fuzz.
%%%
%%% `parse_ack/1` and `parse_newlink_ifindex/1` handle kernel
%%% responses on the RTNETLINK socket (ipvlan slave create/delete,
%%% ifindex lookup).  If they crash on unexpected kernel replies
%%% the container network setup dies mid-spawn.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_netlink_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

parse_ack_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_ack_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

parse_newlink_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_newlink_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

prop_parse_ack_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> erlkoenig_netlink:parse_ack(Bin) end, Bin)).

prop_parse_newlink_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() ->
            erlkoenig_netlink:parse_newlink_ifindex(Bin)
        end, Bin)).

run_safely(F, Label) ->
    Self = self(),
    Pid = spawn(fun() ->
        R = try F() of
                V -> {ok, V}
            catch
                C:E:_ -> {crash, C, E}
            end,
        Self ! {self(), R}
    end),
    receive
        {Pid, {ok, _}} -> true;
        {Pid, {crash, C, E}} ->
            io:format(user, "CRASH ~p:~p on ~p~n", [C, E, Label]),
            false
    after 2000 ->
        exit(Pid, kill),
        io:format(user, "parse hung on ~p~n", [Label]),
        false
    end.
