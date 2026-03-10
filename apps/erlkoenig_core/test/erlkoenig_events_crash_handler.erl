%%%-------------------------------------------------------------------
%%% @doc Test fixture: gen_event handler that crashes on any event.
%%%
%%% Used by erlkoenig_events_tests to verify crash isolation:
%%% a crashing handler must be removed without taking down the bus.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_events_crash_handler).

-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2]).

init([]) ->
    {ok, #{}}.

handle_event(_Event, _State) ->
    error(intentional_crash).

handle_call(_Request, State) ->
    {ok, ok, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.
