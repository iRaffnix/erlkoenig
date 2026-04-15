%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_admission.
%%%
%%% Exercises host-wide cap, per-zone cap, queueing behaviour,
%%% timeout, release, and idempotence.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_admission_tests).

-include_lib("eunit/include/eunit.hrl").

admission_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun t_acquire_under_cap/1,
      fun t_acquire_at_cap_blocks_then_times_out/1,
      fun t_release_unblocks_waiter/1,
      fun t_per_zone_cap_independent_of_host/1,
      fun t_queue_full_rejects_immediately/1,
      fun t_release_unknown_token_noop/1,
      fun t_snapshot_reflects_state/1,
      fun t_zero_host_cap_means_unlimited/1]}.

%%--------------------------------------------------------------------
%% Fixture
%%--------------------------------------------------------------------

setup() ->
    ok = application:set_env(erlkoenig, admission_max_host, 2),
    ok = application:set_env(erlkoenig, admission_max_per_zone, 0),
    ok = application:set_env(erlkoenig, admission_queue_limit, 5),
    {ok, _} = erlkoenig_admission:start_link(),
    #{}.

cleanup(_) ->
    case whereis(erlkoenig_admission) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid, normal, 5_000)
    end,
    _ = application:unset_env(erlkoenig, admission_max_host),
    _ = application:unset_env(erlkoenig, admission_max_per_zone),
    _ = application:unset_env(erlkoenig, admission_queue_limit),
    ok.

%%--------------------------------------------------------------------
%% Tests
%%--------------------------------------------------------------------

t_acquire_under_cap(_) ->
    ?_test(begin
        {ok, T} = erlkoenig_admission:acquire(host, 1_000),
        ?assert(is_reference(T)),
        ok = erlkoenig_admission:release(T)
    end).

t_acquire_at_cap_blocks_then_times_out(_) ->
    ?_test(begin
        {ok, _T1} = erlkoenig_admission:acquire(host, 1_000),
        {ok, _T2} = erlkoenig_admission:acquire(host, 1_000),
        %% Cap of 2 — third acquire should time out quickly.
        ?assertEqual({error, timeout},
                     erlkoenig_admission:acquire(host, 100))
    end).

t_release_unblocks_waiter(_) ->
    ?_test(begin
        {ok, T1} = erlkoenig_admission:acquire(host, 1_000),
        {ok, _T2} = erlkoenig_admission:acquire(host, 1_000),
        Self = self(),
        Waiter = spawn_link(fun() ->
            Res = erlkoenig_admission:acquire(host, 2_000),
            Self ! {waiter_done, Res}
        end),
        %% Give the waiter a moment to enqueue.
        timer:sleep(100),
        ok = erlkoenig_admission:release(T1),
        receive
            {waiter_done, {ok, _}} -> ok;
            {waiter_done, Other} -> ?assert(false, {unexpected, Other})
        after 2_000 ->
            ?assert(false, waiter_didnt_unblock)
        end,
        unlink(Waiter)
    end).

t_per_zone_cap_independent_of_host(_) ->
    ?_test(begin
        ok = gen_server:stop(erlkoenig_admission, normal, 5_000),
        ok = application:set_env(erlkoenig, admission_max_host, 10),
        ok = application:set_env(erlkoenig, admission_max_per_zone, 1),
        {ok, _} = erlkoenig_admission:start_link(),
        {ok, _Ta} = erlkoenig_admission:acquire(<<"z-a">>, 1_000),
        %% Same zone a second time → blocks (cap 1).
        ?assertEqual({error, timeout},
                     erlkoenig_admission:acquire(<<"z-a">>, 100)),
        %% Different zone fine (still under host cap of 10).
        {ok, _Tb} = erlkoenig_admission:acquire(<<"z-b">>, 1_000)
    end).

t_queue_full_rejects_immediately(_) ->
    ?_test(begin
        %% Fill the cap of 2 and the queue of 5.
        {ok, _} = erlkoenig_admission:acquire(host, 1_000),
        {ok, _} = erlkoenig_admission:acquire(host, 1_000),
        lists:foreach(
            fun(_) ->
                spawn(fun() -> erlkoenig_admission:acquire(host, 10_000) end)
            end, lists:seq(1, 5)),
        %% Let the queue settle.
        timer:sleep(200),
        ?assertEqual({error, queue_full},
                     erlkoenig_admission:acquire(host, 100))
    end).

t_release_unknown_token_noop(_) ->
    ?_test(begin
        %% Unknown token must not crash the gen_server.
        ok = erlkoenig_admission:release(make_ref()),
        Snap = erlkoenig_admission:snapshot(),
        ?assertEqual(0, maps:get(host_in_flight, Snap))
    end).

t_snapshot_reflects_state(_) ->
    ?_test(begin
        Initial = erlkoenig_admission:snapshot(),
        ?assertEqual(0, maps:get(host_in_flight, Initial)),
        {ok, T} = erlkoenig_admission:acquire(<<"z-x">>, 1_000),
        After = erlkoenig_admission:snapshot(),
        ?assertEqual(1, maps:get(host_in_flight, After)),
        ?assertEqual(#{<<"z-x">> => 1}, maps:get(zone_in_flight, After)),
        ok = erlkoenig_admission:release(T),
        timer:sleep(20),  %% cast
        Final = erlkoenig_admission:snapshot(),
        ?assertEqual(0, maps:get(host_in_flight, Final))
    end).

t_zero_host_cap_means_unlimited(_) ->
    ?_test(begin
        ok = gen_server:stop(erlkoenig_admission, normal, 5_000),
        ok = application:set_env(erlkoenig, admission_max_host, 0),
        {ok, _} = erlkoenig_admission:start_link(),
        %% Blast a bunch through without blocking.
        lists:foreach(
            fun(_) ->
                {ok, T} = erlkoenig_admission:acquire(host, 1_000),
                ok = erlkoenig_admission:release(T)
            end, lists:seq(1, 50))
    end).
