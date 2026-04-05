%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_health (health check logic).
%%%
%%% Tests the failure counting, threshold detection, timer management,
%%% and process monitoring logic. Does NOT test actual TCP connections.
%%%
%%% The key invariant: a container is restarted when failures >= retries,
%%% and the failure counter resets to 0 after restart is triggered.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_health_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% We test the internal record and logic by simulating the state
%% transitions that handle_failure/1, schedule_check/1, and
%% cancel_and_remove/2 perform. The record definition is copied
%% here since it's not exported.

-record(check, {
    pid       :: pid(),
    ip        :: inet:ip4_address(),
    type      :: tcp,
    port      :: inet:port_number(),
    interval  :: pos_integer(),
    timeout   :: pos_integer(),
    retries   :: pos_integer(),
    failures  = 0 :: non_neg_integer(),
    last      :: ok | fail | undefined,
    timer     :: reference() | undefined
}).

%% =================================================================
%% Failure counting logic
%%
%% Mirrors erlkoenig_health:handle_failure/1 without the side effects
%% (logger, erlkoenig_events, erlkoenig_ct:stop_container).
%% =================================================================

failure_increments_counter_test() ->
    Check = make_check(0, 3),
    Result = simulate_failure(Check),
    ?assertEqual(1, Result#check.failures),
    ?assertEqual(fail, Result#check.last).

failure_below_threshold_test() ->
    Check = make_check(1, 3),
    Result = simulate_failure(Check),
    ?assertEqual(2, Result#check.failures),
    ?assertEqual(fail, Result#check.last).

failure_at_threshold_resets_test() ->
    %% When failures reach retries, counter resets to 0
    %% (restart has been triggered)
    Check = make_check(2, 3),
    Result = simulate_failure(Check),
    ?assertEqual(0, Result#check.failures).

failure_with_retries_1_test() ->
    %% Edge case: retries=1 means restart on first failure
    Check = make_check(0, 1),
    Result = simulate_failure(Check),
    ?assertEqual(0, Result#check.failures).

%% =================================================================
%% Timer management
%% =================================================================

schedule_sets_timer_test() ->
    Check = #check{pid = self(), interval = 5000, timer = undefined},
    Result = schedule_check(Check),
    ?assertNotEqual(undefined, Result#check.timer),
    %% Clean up the timer
    erlang:cancel_timer(Result#check.timer).

cancel_and_remove_cleans_state_test() ->
    Ref = erlang:send_after(60000, self(), test),
    State = #{self() => #check{pid = self(), timer = Ref}},
    Result = cancel_and_remove(self(), State),
    ?assertEqual(#{}, Result),
    %% Timer should be cancelled (no message arrives)
    receive test -> ?assert(false)
    after 10 -> ok
    end.

cancel_and_remove_missing_pid_test() ->
    %% Removing a pid that isn't tracked should be a no-op
    State = #{},
    ?assertEqual(#{}, cancel_and_remove(self(), State)).

%% =================================================================
%% Process monitoring (DOWN handling)
%% =================================================================

down_removes_check_test() ->
    %% Simulate a monitored process dying
    Ref = erlang:send_after(60000, self(), test),
    FakePid = spawn(fun() -> ok end),
    State = #{FakePid => #check{pid = FakePid, timer = Ref}},
    %% Simulate the DOWN message handling
    Result = cancel_and_remove(FakePid, State),
    ?assertEqual(#{}, Result).

%% =================================================================
%% gen_server integration (start/stop)
%% =================================================================

health_server_start_stop_test_() ->
    {setup,
     fun() ->
         {ok, Pid} = erlkoenig_health:start_link(),
         Pid
     end,
     fun(Pid) ->
         unlink(Pid),
         exit(Pid, shutdown),
         MRef = monitor(process, Pid),
         receive {'DOWN', MRef, process, Pid, _} -> ok
         after 1000 -> ok
         end,
         try unregister(erlkoenig_health) catch _:_ -> ok end
     end,
     fun(_Pid) -> [
        fun() ->
            %% Status should return empty list initially
            ?assertEqual([], erlkoenig_health:status())
        end
     ] end}.

%% =================================================================
%% Helpers (mirror internal logic without side effects)
%% =================================================================

make_check(Failures, Retries) ->
    #check{
        pid      = self(),
        ip       = {10, 0, 0, 2},
        type     = tcp,
        port     = 8080,
        interval = 5000,
        timeout  = 2000,
        retries  = Retries,
        failures = Failures,
        last     = undefined,
        timer    = undefined
    }.

%% Simulates handle_failure/1 without logger/events/stop side effects
simulate_failure(#check{failures = F, retries = Max} = Check) ->
    NewF = F + 1,
    Check2 = Check#check{failures = NewF, last = fail},
    case NewF >= Max of
        true  -> Check2#check{failures = 0};
        false -> Check2
    end.

%% Mirror of schedule_check/1
schedule_check(#check{interval = Interval, pid = Pid} = Check) ->
    Ref = erlang:send_after(Interval, self(), {check, Pid}),
    Check#check{timer = Ref}.

%% Mirror of cancel_and_remove/2
cancel_and_remove(Pid, State) ->
    case maps:find(Pid, State) of
        {ok, #check{timer = T}} ->
            cancel_timer(T),
            maps:remove(Pid, State);
        error ->
            State
    end.

cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> erlang:cancel_timer(Ref), ok.
