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

-module(erlkoenig_event_log).
-moduledoc """
Default event handler that logs events.

Installed automatically by erlkoenig_events:start_link/0.
Logs container lifecycle events via logger.
""".

-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2]).

%%%===================================================================
%%% gen_event callbacks
%%%===================================================================

-spec init(list()) -> {ok, map()}.
init([]) ->
    {ok, #{}}.

-spec handle_event(term(), map()) -> {ok, map()}.
handle_event({container_started, Id, Pid}, State) ->
    logger:info("event: container ~s started (pid=~p)", [Id, Pid]),
    {ok, State};
handle_event({container_stopped, Id, ExitInfo}, State) ->
    logger:info("event: container ~s stopped ~p", [Id, ExitInfo]),
    {ok, State};
handle_event({container_failed, Id, Reason}, State) ->
    logger:warning("event: container ~s failed: ~p", [Id, Reason]),
    {ok, State};
handle_event({container_restarting, Id, Attempt}, State) ->
    logger:info("event: container ~s restarting (attempt ~p)", [Id, Attempt]),
    {ok, State};
handle_event({container_oom, Id}, State) ->
    logger:warning("event: container ~s killed by OOM", [Id]),
    {ok, State};
handle_event(_Event, State) ->
    {ok, State}.

-spec handle_call(term(), map()) -> {ok, term(), map()}.
handle_call(_Request, State) ->
    {ok, {error, unknown}, State}.

-spec handle_info(term(), map()) -> {ok, map()}.
handle_info(_Info, State) ->
    {ok, State}.

-spec terminate(term(), map()) -> ok.
terminate(_Reason, _State) ->
    ok.
