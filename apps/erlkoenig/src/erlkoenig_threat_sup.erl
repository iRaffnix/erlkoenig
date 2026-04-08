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

-module(erlkoenig_threat_sup).
-moduledoc """
Dynamic supervisor for per-IP threat actor processes.

Manages erlkoenig_threat_actor children (one per suspicious source IP).
Children are temporary — a crashed actor is not restarted; the next
connection event for that IP starts a fresh one.

The ETS registry (IP → Pid) is NOT owned by this supervisor. It is
created by erlkoenig_nft_ct_guard, which is a stable, long-lived
process. If this supervisor crashes and restarts, the registry
survives.
""".

-behaviour(supervisor).

-export([start_link/0, start_actor/2]).
-export([init/1]).

-define(REGISTRY, erlkoenig_threat_actor_registry).

-doc "Start the dynamic supervisor.".
-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc """
Start a new threat actor for the given IP.

Called from ensure_actor/1 in ct_guard after reserving the ETS slot.
Config contains detection thresholds (flood, scan, honeypot, etc.).
""".
-spec start_actor(binary(), map()) -> {ok, pid()} | {error, term()}.
start_actor(IP, Config) ->
    supervisor:start_child(?MODULE, [IP, Config#{registry => ?REGISTRY}]).

init([]) ->
    SupFlags = #{
        strategy => simple_one_for_one,
        intensity => 100,
        period => 1
    },
    ChildSpec = #{
        id => threat_actor,
        start => {erlkoenig_threat_actor, start_link, []},
        restart => temporary,
        shutdown => 1000,
        type => worker,
        modules => [erlkoenig_threat_actor]
    },
    {ok, {SupFlags, [ChildSpec]}}.
