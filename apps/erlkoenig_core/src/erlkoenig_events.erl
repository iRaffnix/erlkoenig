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

-module(erlkoenig_events).
-moduledoc """
Container lifecycle event bus.

A gen_event manager that broadcasts container lifecycle events.
Handlers can be added dynamically at runtime -- a crashing handler
does NOT take down the bus.

Events:
  {container_started,   Id, Pid}          - Container entered running
  {container_stopped,   Id, ExitInfo}     - Container exited normally
  {container_failed,    Id, Reason}       - Container entered failed
  {container_restarting, Id, Attempt}     - Container restart scheduled
  {container_oom,       Id}               - OOM-Kill detected (signal 9)

Usage:
  erlkoenig_events:subscribe(MyHandlerModule, Args).
  erlkoenig_events:unsubscribe(MyHandlerModule, Args).

A default log handler is installed at startup.
""".

%% API
-export([start_link/0,
         notify/1,
         subscribe/2,
         unsubscribe/2,
         which_handlers/0]).

-doc "Start the event manager, linked to the supervisor.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    case gen_event:start_link({local, ?MODULE}) of
        {ok, Pid} ->
            %% Install default handlers.
            gen_event:add_handler(?MODULE, erlkoenig_event_log, []),
            _ = erlkoenig_metrics:subscribe(),
            _ = erlkoenig_policy:subscribe(),
            {ok, Pid};
        Error ->
            Error
    end.

-doc "Send an event to all handlers.".
-spec notify(term()) -> ok.
notify(Event) ->
    gen_event:notify(?MODULE, Event).

-doc "Add an event handler.".
-spec subscribe(module(), term()) -> ok | {error, term()}.
subscribe(Handler, Args) ->
    gen_event:add_handler(?MODULE, Handler, Args).

-doc "Remove an event handler.".
-spec unsubscribe(module(), term()) -> ok | {error, term()}.
unsubscribe(Handler, Args) ->
    gen_event:delete_handler(?MODULE, Handler, Args).

-doc "List installed handlers (for debugging).".
-spec which_handlers() -> [module()].
which_handlers() ->
    gen_event:which_handlers(?MODULE).
