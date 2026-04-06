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

-module(erlkoenig_policy).
-moduledoc """
Container runtime policy engine.

Evaluates eBPF metric events against per-container policies
and triggers actions (kill, restart, alert) when thresholds
are exceeded.

Installed as a gen_event handler on erlkoenig_events.
Each container's policy is stored when the container starts
and removed when it stops.
""".
-behaviour(gen_event).

-export([subscribe/0,
         unsubscribe/0,
         register_policy/2,
         unregister_policy/1]).

-export([init/1,
         handle_event/2,
         handle_call/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(TABLE, erlkoenig_policy_tab).

%% Per-container policy state
-record(pol, {
    id              :: binary(),
    policy          :: map(),
    %% Fork rate tracking (sliding window)
    fork_times = [] :: [integer()],  %% monotonic timestamps of recent forks
    container_pid   :: pid() | undefined
}).

%% =================================================================
%% Public API
%% =================================================================

-spec subscribe() -> ok | {error, term()}.
subscribe() ->
    case ets:info(?TABLE) of
        undefined ->
            _ = ets:new(?TABLE, [named_table, public, set,
                                  {keypos, #pol.id}]);
        _ ->
            ok
    end,
    gen_event:add_handler(erlkoenig_events, ?MODULE, []).

-spec unsubscribe() -> ok.
unsubscribe() ->
    gen_event:delete_handler(erlkoenig_events, ?MODULE, []).

-doc "Register a policy for a container. Called from erlkoenig_ct when a container with a policy starts.".
-spec register_policy(binary(), map()) -> ok.
register_policy(ContainerId, Policy) ->
    %% self() is the gen_statem (erlkoenig_ct) calling this during setup
    ets:insert(?TABLE, #pol{id = ContainerId, policy = Policy,
                            container_pid = self()}),
    ok.

-doc "Remove policy for a container.".
-spec unregister_policy(binary()) -> ok.
unregister_policy(ContainerId) ->
    ets:delete(?TABLE, ContainerId),
    ok.

%% =================================================================
%% gen_event callbacks
%% =================================================================

init([]) ->
    {ok, #{}}.

handle_event({container_metrics, Id, _Name, Event}, State) ->
    handle_event({container_metrics, Id, Event}, State);

handle_event({container_metrics, Id, Event}, State) ->
    case ets:lookup(?TABLE, Id) of
        [Pol] -> evaluate(Id, Event, Pol);
        []    -> ok
    end,
    {ok, State};

handle_event({container_started, Id, _Name, Pid}, State) ->
    case ets:lookup(?TABLE, Id) of
        [Pol] ->
            ets:insert(?TABLE, Pol#pol{container_pid = Pid});
        [] ->
            ok
    end,
    {ok, State};

handle_event({container_stopped, Id, _Name, _}, State) ->
    ets:delete(?TABLE, Id),
    {ok, State};

handle_event(_, State) ->
    {ok, State}.

handle_call(_, State) ->
    {ok, {error, unknown_call}, State}.

handle_info(_, State) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% =================================================================
%% Policy evaluation
%% =================================================================

evaluate(Id, #{type := fork} = _Event, Pol) ->
    Policy = Pol#pol.policy,
    Now = erlang:monotonic_time(millisecond),

    %% Track fork timestamp
    Forks = [Now | Pol#pol.fork_times],
    %% Keep only last 60 seconds of forks
    Cutoff60 = Now - 60_000,
    Forks2 = lists:filter(fun(T) -> T > Cutoff60 end, Forks),
    ets:insert(?TABLE, Pol#pol{fork_times = Forks2}),

    %% Check per-second rate
    case maps:get(max_forks_per_sec, Policy, undefined) of
        undefined -> ok;
        MaxPerSec ->
            Cutoff1 = Now - 1000,
            CountSec = length(lists:filter(fun(T) -> T > Cutoff1 end, Forks2)),
            if CountSec > MaxPerSec ->
                fork_flood_action(Id, Policy, CountSec, <<"per_sec">>);
               true -> ok
            end
    end,

    %% Check per-minute rate
    case maps:get(max_forks_per_min, Policy, undefined) of
        undefined -> ok;
        MaxPerMin ->
            CountMin = length(Forks2),
            if CountMin > MaxPerMin ->
                fork_flood_action(Id, Policy, CountMin, <<"per_min">>);
               true -> ok
            end
    end;

evaluate(Id, #{type := exec} = Ev, Pol) ->
    Comm = maps:get(comm, Ev, <<>>),
    Policy = Pol#pol.policy,
    case maps:get(allowed_comms, Policy, undefined) of
        undefined -> ok;
        AllowedList ->
            case lists:member(Comm, AllowedList) of
                true -> ok;
                false ->
                    Action = maps:get(on_unexpected_exec, Policy, alert),
                    logger:warning("container ~s: unexpected exec: ~s "
                                   "(allowed: ~p, action: ~p)",
                                   [Id, Comm, AllowedList, Action]),
                    erlkoenig_events:notify({policy_violation, Id,
                                             {unexpected_exec, Comm, Action}}),
                    execute_action(Id, Action)
            end
    end;

evaluate(Id, #{type := oom}, Pol) ->
    Policy = Pol#pol.policy,
    Action = maps:get(on_oom, Policy, alert),
    logger:warning("container ~s: OOM kill detected (action: ~p)",
                   [Id, Action]),
    erlkoenig_events:notify({policy_violation, Id, {oom, Action}}),
    execute_action(Id, Action);

evaluate(_Id, _Event, _Pol) ->
    ok.

%% =================================================================
%% Actions
%% =================================================================

fork_flood_action(Id, Policy, Count, Window) ->
    Action = maps:get(on_fork_flood, Policy, alert),
    logger:warning("container ~s: fork flood detected: ~p forks ~s "
                   "(action: ~p)", [Id, Count, Window, Action]),
    erlkoenig_events:notify({policy_violation, Id,
                             {fork_flood, Count, Window, Action}}),
    execute_action(Id, Action).

execute_action(_Id, alert) ->
    %% Alert only — event already fired, nothing more to do
    ok;
execute_action(Id, kill) ->
    %% Kill container immediately (no restart)
    case find_container_pid(Id) of
        {ok, Pid} ->
            logger:error("container ~s: policy KILL", [Id]),
            catch erlkoenig_ct:kill(Pid, 9),
            ok;
        error ->
            ok
    end;
execute_action(Id, restart) ->
    %% Stop gracefully — restart policy will handle restart
    case find_container_pid(Id) of
        {ok, Pid} ->
            logger:warning("container ~s: policy RESTART", [Id]),
            catch erlkoenig_ct:stop_container(Pid),
            ok;
        error ->
            ok
    end;
execute_action(Id, Unknown) ->
    %% Catch-all: unknown action — log and ignore (don't crash handler)
    logger:error("container ~s: unknown policy action: ~p", [Id, Unknown]),
    ok.

find_container_pid(Id) ->
    case ets:lookup(?TABLE, Id) of
        [#pol{container_pid = Pid}] when is_pid(Pid) -> {ok, Pid};
        _ -> error
    end.
