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

%%%-------------------------------------------------------------------
%% @doc erlkoenig top level supervisor.
%%
%% Uses a simple_one_for_one strategy for dynamic container children.
%% Each child is a erlkoenig_ct gen_statem started via start_container/2.
%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_container/2]).

%% supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @doc Start a new container as a child of erlkoenig_ct_sup.
-spec start_container(binary(), erlkoenig_core:spawn_opts()) -> {ok, pid()} | {error, term()}.
start_container(BinaryPath, Opts) ->
    supervisor:start_child(erlkoenig_ct_sup, [BinaryPath, Opts]).

%%%===================================================================
%%% supervisor callbacks
%%%===================================================================

init([]) ->
    %% erlkoenig_sup (rest_for_one)
    %%   ├── pg scope (erlkoenig_pg)
    %%   ├── erlkoenig_zone (zone registry, must start before zone_sup)
    %%   ├── erlkoenig_zone_sup (one_for_one, per-zone bridge/pool/dns)
    %%   ├── erlkoenig_cgroup
    %%   ├── erlkoenig_events
    %%   ├── erlkoenig_health
    %%   ├── erlkoenig_audit
    %%   ├── erlkoenig_pki
    %%   ├── erlkoenig_ctl
    %%   └── erlkoenig_ct_sup (simple_one_for_one for containers)
    SupFlags = #{
        strategy => rest_for_one,
        intensity => 5,
        period => 10
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
    CtlSpec = #{
        id => erlkoenig_ctl,
        start => {erlkoenig_ctl, start_link, []},
        restart => permanent,
        type => worker
    },
    CtSupSpec = #{
        id => erlkoenig_ct_sup,
        start => {supervisor, start_link, [{local, erlkoenig_ct_sup}, ?MODULE, ct_sup]},
        restart => permanent,
        type => supervisor
    },
    {ok, {SupFlags, [PgSpec, ZoneSpec, ZoneSupSpec, CgroupSpec, EventsSpec, HealthSpec, AuditSpec, PkiSpec, CtlSpec, CtSupSpec]}};

init(ct_sup) ->
    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 5,
        period => 10
    },
    ChildSpec = #{
        id => erlkoenig_ct,
        start => {erlkoenig_ct, start_link, []},
        restart => temporary,
        shutdown => 10_000,
        type => worker
    },
    {ok, {SupFlags, [ChildSpec]}}.
