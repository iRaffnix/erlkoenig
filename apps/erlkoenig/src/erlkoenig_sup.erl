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

-module(erlkoenig_sup).
-moduledoc """
Erlkoenig top level supervisor.

Container processes live inside per-pod supervisors (erlkoenig_pod_sup),
which are dynamic children of erlkoenig_pod_sup_sup.

See ADR-0013 for the pod supervision design.
""".

-behaviour(supervisor).

%% API
-export([start_link/0, start_container/2, start_pod/3]).

%% supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc "Start a single container in an isolated pod (backwards-compatible).".
-spec start_container(binary(), erlkoenig:spawn_opts()) -> {ok, pid()} | {error, term()}.
start_container(BinaryPath, Opts) ->
    %% Wrap single container in a one_for_one pod supervisor
    PodName = maps:get(name, Opts, <<"unnamed">>),
    case erlkoenig_pod_sup:start_pod(PodName, one_for_one,
                                      [{BinaryPath, Opts}]) of
        {ok, PodPid} ->
            %% Return the container pid (first child of pod sup)
            case supervisor:which_children(PodPid) of
                [{_, CtPid, _, _}] when is_pid(CtPid) -> {ok, CtPid};
                _ -> {ok, PodPid}
            end;
        Error -> Error
    end.

-doc "Start a pod with multiple containers under a shared supervisor.".
-spec start_pod(binary(), atom(), [{binary(), map()}]) -> {ok, pid()} | {error, term()}.
start_pod(PodName, Strategy, Children) ->
    erlkoenig_pod_sup:start_pod(PodName, Strategy, Children).

%%%===================================================================
%%% supervisor callbacks
%%%===================================================================

init([]) ->
    %% erlkoenig_sup (rest_for_one)
    %%   ├── pg scope (erlkoenig_pg)
    %%   ├── erlkoenig_zone (zone registry, must start before zone_sup)
    %%   ├── erlkoenig_zone_sup (one_for_one, per-zone ip_pool + dns)
    %%   ├── erlkoenig_cgroup
    %%   ├── erlkoenig_events
    %%   ├── erlkoenig_health
    %%   ├── erlkoenig_audit
    %%   ├── erlkoenig_pki
    %%   ├── erlkoenig_nft_sup (firewall subtree)
    %%   ├── erlkoenig_amqp_sup (optional, AMQP integration, ADR-0014)
    %%   └── erlkoenig_pod_sup_sup (simple_one_for_one for pod supervisors)
    %% `auto_shutdown => any_significant`: the root shuts down cleanly
    %% when any child marked `significant => true` terminates. Only
    %% `erlkoenig_nft_sup` carries that flag today — a definitive
    %% firewall failure takes the runtime offline rather than leaving
    %% containers running without the expected network policy.
    SupFlags = #{
        strategy => rest_for_one,
        intensity => 5,
        period => 10,
        auto_shutdown => any_significant
    },
    PgSpec = #{
        id => erlkoenig_pg,
        start => {pg, start_link, [erlkoenig_pg]},
        restart => permanent,
        type => worker
    },
    ZoneSpec = #{
        id => erlkoenig_zone,
        start => {erlkoenig_zone, start_link, []},
        restart => permanent,
        type => worker
    },
    ZoneSupSpec = #{
        id => erlkoenig_zone_sup,
        start => {erlkoenig_zone_sup, start_link, []},
        restart => permanent,
        type => supervisor
    },
    CgroupSpec = #{
        id => erlkoenig_cgroup,
        start => {erlkoenig_cgroup, start_link, []},
        restart => permanent,
        type => worker
    },
    EventsSpec = #{
        id => erlkoenig_events,
        start => {erlkoenig_events, start_link, []},
        restart => permanent,
        type => worker
    },
    HealthSpec = #{
        id => erlkoenig_health,
        start => {erlkoenig_health, start_link, []},
        restart => permanent,
        type => worker
    },
    AuditSpec = #{
        id => erlkoenig_audit,
        start => {erlkoenig_audit, start_link, []},
        restart => permanent,
        type => worker
    },
    PkiSpec = #{
        id => erlkoenig_pki,
        start => {erlkoenig_pki, start_link, []},
        restart => permanent,
        type => worker
    },
    %% `significant => true` + `restart => transient`: firewall subtree
    %% terminating terminally (own auto_shutdown from the inside) takes
    %% the whole runtime down fail-closed. A transient crash still
    %% restarts normally.
    NftSupSpec = #{
        id => erlkoenig_nft_sup,
        start => {erlkoenig_nft_sup, start_link, []},
        restart => transient,
        significant => true,
        type => supervisor,
        shutdown => infinity
    },
    QuarantineSpec = #{
        id => erlkoenig_quarantine,
        start => {erlkoenig_quarantine, start_link, []},
        restart => permanent,
        type => worker
    },
    AdmissionSpec = #{
        id => erlkoenig_admission,
        start => {erlkoenig_admission, start_link, []},
        restart => permanent,
        type => worker
    },
    VolumeStoreSpec = #{
        id => erlkoenig_volume_store,
        start => {erlkoenig_volume_store, start_link, []},
        restart => permanent,
        type => worker
    },
    VolumeStatsSpec = #{
        id => erlkoenig_volume_stats,
        start => {erlkoenig_volume_stats, start_link, []},
        restart => permanent,
        type => worker
    },
    PodSupSupSpec = #{
        id => erlkoenig_pod_sup_sup,
        start => {supervisor, start_link, [{local, erlkoenig_pod_sup_sup}, ?MODULE, pod_sup_sup]},
        restart => permanent,
        type => supervisor
    },
    {ok, {SupFlags, [PgSpec, ZoneSpec, ZoneSupSpec, CgroupSpec, EventsSpec,
                     HealthSpec, AuditSpec, PkiSpec, NftSupSpec,
                     QuarantineSpec, AdmissionSpec,
                     VolumeStoreSpec, VolumeStatsSpec, PodSupSupSpec]}};

init(pod_sup_sup) ->
    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 10,
        period => 60
    },
    ChildSpec = #{
        id => erlkoenig_pod_sup,
        start => {erlkoenig_pod_sup, start_link, []},
        restart => temporary,
        shutdown => 30_000,
        type => supervisor
    },
    {ok, {SupFlags, [ChildSpec]}}.
