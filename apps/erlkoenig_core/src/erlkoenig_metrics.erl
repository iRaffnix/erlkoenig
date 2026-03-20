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

-module(erlkoenig_metrics).
-moduledoc """
eBPF tracepoint metrics aggregation.

Subscribes to the erlkoenig_events bus and aggregates raw
metrics events (fork/exec/exit/oom) per container into
useful statistics.

Events arrive as {container_metrics, ContainerId, EventMap}
from erlkoenig_ct (forwarded from the C runtime's BPF ring buffer).
""".
-behaviour(gen_event).

%% Public API
-export([subscribe/0,
         unsubscribe/0,
         stats/1,
         all_stats/0,
         reset/1]).

%% gen_event callbacks
-export([init/1,
         handle_event/2,
         handle_call/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(TABLE, erlkoenig_metrics_tab).

%% Per-container metrics record stored in ETS
-record(metrics, {
    id            :: binary(),
    fork_count    = 0 :: non_neg_integer(),
    exec_count    = 0 :: non_neg_integer(),
    exit_count    = 0 :: non_neg_integer(),
    oom_count     = 0 :: non_neg_integer(),
    last_fork_ts  = 0 :: non_neg_integer(),
    last_exec_ts  = 0 :: non_neg_integer(),
    last_exit_ts  = 0 :: non_neg_integer(),
    last_oom_ts   = 0 :: non_neg_integer(),
    last_comm     = <<>> :: binary()
}).

%% =================================================================
%% Public API
%% =================================================================

-doc "Install the metrics handler on the erlkoenig_events bus.".
-spec subscribe() -> ok | {error, term()}.
subscribe() ->
    case ets:info(?TABLE) of
        undefined ->
            _ = ets:new(?TABLE, [named_table, public, set,
                                  {keypos, #metrics.id}]);
        _ ->
            ok
    end,
    gen_event:add_handler(erlkoenig_events, ?MODULE, []).

-doc "Remove the metrics handler.".
-spec unsubscribe() -> ok.
unsubscribe() ->
    gen_event:delete_handler(erlkoenig_events, ?MODULE, []).

-doc "Get aggregated metrics for a container.".
-spec stats(binary()) -> {ok, map()} | {error, not_found}.
stats(ContainerId) ->
    case ets:lookup(?TABLE, ContainerId) of
        [M] -> {ok, metrics_to_map(M)};
        []  -> {error, not_found}
    end.

-doc "Get metrics for all containers.".
-spec all_stats() -> #{binary() => map()}.
all_stats() ->
    ets:foldl(
      fun(M, Acc) ->
              Acc#{M#metrics.id => metrics_to_map(M)}
      end, #{}, ?TABLE).

-doc "Reset metrics for a container (e.g. on restart).".
-spec reset(binary()) -> ok.
reset(ContainerId) ->
    ets:delete(?TABLE, ContainerId),
    ok.

%% =================================================================
%% gen_event callbacks
%% =================================================================

init([]) ->
    {ok, #{}}.

handle_event({container_metrics, Id, #{type := fork} = Ev}, State) ->
    update_metrics(Id, fun(M) ->
        M#metrics{fork_count  = M#metrics.fork_count + 1,
                  last_fork_ts = maps:get(timestamp_ns, Ev, 0)}
    end),
    {ok, State};

handle_event({container_metrics, Id, #{type := exec} = Ev}, State) ->
    update_metrics(Id, fun(M) ->
        M#metrics{exec_count  = M#metrics.exec_count + 1,
                  last_exec_ts = maps:get(timestamp_ns, Ev, 0),
                  last_comm    = maps:get(comm, Ev, <<>>)}
    end),
    {ok, State};

handle_event({container_metrics, Id, #{type := exit} = Ev}, State) ->
    update_metrics(Id, fun(M) ->
        M#metrics{exit_count  = M#metrics.exit_count + 1,
                  last_exit_ts = maps:get(timestamp_ns, Ev, 0)}
    end),
    {ok, State};

handle_event({container_metrics, Id, #{type := oom} = Ev}, State) ->
    update_metrics(Id, fun(M) ->
        M#metrics{oom_count  = M#metrics.oom_count + 1,
                  last_oom_ts = maps:get(timestamp_ns, Ev, 0)}
    end),
    {ok, State};

handle_event({container_stopped, Id, _}, State) ->
    %% Clean up metrics 30s after stop (allows post-mortem inspection).
    %% Timer is fire-and-forget; if handler restarts, entries are orphaned
    %% but bounded by container count.
    erlang:send_after(30_000, erlkoenig_events, {cleanup_metrics, Id}),
    {ok, State};

handle_event(_, State) ->
    {ok, State}.

handle_call({stats, Id}, State) ->
    Reply = case ets:lookup(?TABLE, Id) of
        [M] -> {ok, metrics_to_map(M)};
        []  -> {error, not_found}
    end,
    {ok, Reply, State};

handle_call(_, State) ->
    {ok, {error, unknown_call}, State}.

handle_info({cleanup_metrics, Id}, State) ->
    ets:delete(?TABLE, Id),
    {ok, State};
handle_info(_, State) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% =================================================================
%% Internal
%% =================================================================

%% Safe: gen_event dispatches events sequentially to each handler,
%% so this read-modify-write is not concurrent within this handler.
%% External readers (stats/1) see a consistent snapshot per ETS read.
update_metrics(Id, Fun) ->
    M = case ets:lookup(?TABLE, Id) of
        [Existing] -> Existing;
        []         -> #metrics{id = Id}
    end,
    ets:insert(?TABLE, Fun(M)).

metrics_to_map(#metrics{} = M) ->
    #{fork_count  => M#metrics.fork_count,
      exec_count  => M#metrics.exec_count,
      exit_count  => M#metrics.exit_count,
      oom_count   => M#metrics.oom_count,
      last_fork   => M#metrics.last_fork_ts,
      last_exec   => M#metrics.last_exec_ts,
      last_exit   => M#metrics.last_exit_ts,
      last_oom    => M#metrics.last_oom_ts,
      last_comm   => M#metrics.last_comm}.
