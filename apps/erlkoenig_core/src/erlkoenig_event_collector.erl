%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(erlkoenig_event_collector).
-moduledoc """
Collects events into an ETS table.

A gen_event handler that stores all events with timestamps in an
ETS table for later inspection. Useful for demos and testing.

Usage:
  Tab = ets:new(events, [ordered_set, public]),
  erlkoenig_core:subscribe(erlkoenig_event_collector, [Tab]).
  %% ... events are now stored in Tab as {MonotonicTime, Event} ...
  erlkoenig_core:unsubscribe(erlkoenig_event_collector, [Tab]).
""".

-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2]).

%%%===================================================================
%%% gen_event callbacks
%%%===================================================================

-spec init([ets:tid()]) -> {ok, map()}.
init([Tab]) ->
    {ok, #{tab => Tab}}.

-spec handle_event(term(), map()) -> {ok, map()}.
handle_event(Event, #{tab := Tab} = State) ->
    ets:insert(Tab, {erlang:monotonic_time(microsecond), Event}),
    {ok, State}.

-spec handle_call(term(), map()) -> {ok, term(), map()}.
handle_call(get_count, #{tab := Tab} = State) ->
    {ok, ets:info(Tab, size), State}.

-spec handle_info(term(), map()) -> {ok, map()}.
handle_info(_Info, State) ->
    {ok, State}.

-spec terminate(term(), map()) -> ok.
terminate(_Reason, _State) ->
    ok.
