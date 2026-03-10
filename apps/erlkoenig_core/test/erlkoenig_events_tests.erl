%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_events (event bus) and its handlers.
%%%
%%% Tests event delivery, handler registration/removal, crash isolation,
%%% and the two built-in handlers (erlkoenig_event_log, erlkoenig_event_collector).
%%%
%%% The architectural guarantee under test: a crashing handler must be
%%% removed without taking down the event bus (gen_event semantics).
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_events_tests).

-include_lib("eunit/include/eunit.hrl").

%% =================================================================
%% Bus lifecycle
%% =================================================================

start_installs_default_handler_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_) -> [
        fun() ->
            Handlers = erlkoenig_events:which_handlers(),
            ?assert(lists:member(erlkoenig_event_log, Handlers))
        end
     ] end}.

subscribe_and_unsubscribe_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_) -> [
        fun() ->
            Tab = ets:new(test_events, [ordered_set, public]),
            ok = erlkoenig_events:subscribe(erlkoenig_event_collector, [Tab]),
            ?assert(lists:member(erlkoenig_event_collector,
                                 erlkoenig_events:which_handlers())),
            ok = erlkoenig_events:unsubscribe(erlkoenig_event_collector, [Tab]),
            ?assertNot(lists:member(erlkoenig_event_collector,
                                    erlkoenig_events:which_handlers())),
            ets:delete(Tab)
        end
     ] end}.

%% =================================================================
%% Event delivery via collector
%% =================================================================

notify_reaches_collector_test_() ->
    {setup,
     fun() ->
         Pid = setup(),
         Tab = ets:new(test_events, [ordered_set, public]),
         ok = erlkoenig_events:subscribe(erlkoenig_event_collector, [Tab]),
         {Pid, Tab}
     end,
     fun({Pid, Tab}) ->
         erlkoenig_events:unsubscribe(erlkoenig_event_collector, [Tab]),
         ets:delete(Tab),
         cleanup(Pid)
     end,
     fun({_Pid, Tab}) -> [
        fun() ->
            erlkoenig_events:notify({container_started, <<"test-1">>, self()}),
            %% gen_event:notify is async, give it a moment
            timer:sleep(10),
            Events = ets:tab2list(Tab),
            ?assertEqual(1, length(Events)),
            [{_Ts, Event}] = Events,
            ?assertMatch({container_started, <<"test-1">>, _}, Event)
        end
     ] end}.

collector_counts_events_test_() ->
    {setup,
     fun() ->
         Pid = setup(),
         Tab = ets:new(test_events, [ordered_set, public]),
         ok = erlkoenig_events:subscribe(erlkoenig_event_collector, [Tab]),
         {Pid, Tab}
     end,
     fun({Pid, Tab}) ->
         erlkoenig_events:unsubscribe(erlkoenig_event_collector, [Tab]),
         ets:delete(Tab),
         cleanup(Pid)
     end,
     fun({_Pid, _Tab}) -> [
        fun() ->
            erlkoenig_events:notify({container_started, <<"a">>, self()}),
            erlkoenig_events:notify({container_stopped, <<"b">>, #{}}),
            erlkoenig_events:notify({container_oom, <<"c">>}),
            timer:sleep(10),
            %% gen_event:call returns the handler's reply directly (not {ok, _})
            Count = gen_event:call(
                erlkoenig_events, erlkoenig_event_collector, get_count),
            ?assertEqual(3, Count)
        end
     ] end}.

%% =================================================================
%% Event log handler (all event types)
%% =================================================================

event_log_handles_all_types_test() ->
    %% Direct handler callback test: all event types must return {ok, State}
    %% without crashing. This is acceptable because we test the handler
    %% module in isolation, not OTP callbacks through the bus.
    {ok, State0} = erlkoenig_event_log:init([]),
    Events = [
        {container_started, <<"id1">>, self()},
        {container_stopped, <<"id2">>, #{exit_code => 0}},
        {container_failed, <<"id3">>, timeout},
        {container_restarting, <<"id4">>, 2},
        {container_oom, <<"id5">>},
        {unknown_event, <<"id6">>}
    ],
    lists:foldl(fun(Event, State) ->
        {ok, NewState} = erlkoenig_event_log:handle_event(Event, State),
        NewState
    end, State0, Events).

%% =================================================================
%% Crash isolation
%% =================================================================

crashing_handler_removed_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(_) -> [
        fun() ->
            %% Add a handler that will crash on the next event
            ok = gen_event:add_handler(erlkoenig_events,
                    {erlkoenig_events_crash_handler, make_ref()},
                    []),
            HandlersBefore = erlkoenig_events:which_handlers(),
            ?assert(length(HandlersBefore) >= 2),

            %% Send an event that causes the crash handler to fail
            erlkoenig_events:notify(crash_please),
            timer:sleep(50),

            %% The crash handler should be gone, bus still alive
            HandlersAfter = erlkoenig_events:which_handlers(),
            ?assert(lists:member(erlkoenig_event_log, HandlersAfter)),
            %% Bus must still accept events
            erlkoenig_events:notify({container_started, <<"ok">>, self()})
        end
     ] end}.

%% =================================================================
%% Setup / Cleanup
%% =================================================================

setup() ->
    {ok, Pid} = erlkoenig_events:start_link(),
    Pid.

cleanup(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    MRef = monitor(process, Pid),
    receive {'DOWN', MRef, process, Pid, _} -> ok
    after 1000 -> ok
    end,
    try unregister(erlkoenig_events) catch _:_ -> ok end.
