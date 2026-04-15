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

-module(erlkoenig_pod_sup).
-moduledoc """
Per-pod-instance OTP supervisor.

Each pod deployment gets its own supervisor whose strategy is
determined by the DSL `strategy:` option:

  - `one_for_one`   (:isolated)  — independent containers, self-managed restart
  - `one_for_all`   (:linked)    — one crashes, all restart
  - `rest_for_one`  (:ordered)   — one crashes, it and all later children restart

Children are erlkoenig_ct gen_statem processes. Their restart type
depends on the strategy:

  - `one_for_one`: `temporary` (container manages own restart via gen_statem)
  - otherwise:     `transient` (supervisor manages group restart)

See ADR-0013 for the design rationale.
""".

-behaviour(supervisor).

-export([start_link/3, start_pod/3]).
-export([init/1]).

-doc "Start a pod supervisor for a named pod instance.".
-spec start_link(binary(), atom(), [{binary(), map()}]) ->
    {ok, pid()} | {error, term()}.
start_link(PodName, Strategy, Children) ->
    supervisor:start_link(?MODULE, {PodName, Strategy, Children}).

-doc "Start a pod via the pod_sup_sup dynamic supervisor.".
-spec start_pod(binary(), atom(), [{binary(), map()}]) ->
    {ok, pid()} | {error, term()}.
start_pod(PodName, Strategy, Children) ->
    supervisor:start_child(erlkoenig_pod_sup_sup,
                           [PodName, Strategy, Children]).

init({PodName, Strategy, Children}) ->
    %% Tag ourselves so that external tools (ek pod list) can recover the
    %% pod name from process_info. Supervisor children in the
    %% simple_one_for_one pod_sup_sup all share a single ChildSpec whose
    %% :id field is `undefined`, so the label is the only place the name
    %% survives.
    proc_lib:set_label({erlkoenig_pod, PodName}),
    ChildRestart = case Strategy of
        one_for_one -> temporary;
        _           -> transient
    end,
    SupFlags = #{
        strategy => Strategy,
        intensity => 5,
        period => 60,
        %% Self-terminate when every container below us has exited.
        %% Without this the pod supervisor would linger with no
        %% children after a stop, showing up as a zombie in ek pod list.
        auto_shutdown => all_significant
    },
    ChildSpecs = lists:map(fun({Idx, {BinaryPath, Opts}}) ->
        %% Mark containers in supervised pods so erlkoenig_ct knows
        %% to propagate exits instead of self-managing restarts.
        PodSupervised = (Strategy =/= one_for_one),
        Opts2 = Opts#{pod_supervised => PodSupervised},
        #{
            id => {erlkoenig_ct, Idx},
            start => {erlkoenig_ct, start_link, [BinaryPath, Opts2]},
            restart => ChildRestart,
            shutdown => 10_000,
            type => worker,
            significant => true
        }
    end, lists:enumerate(Children)),
    {ok, {SupFlags, ChildSpecs}}.
