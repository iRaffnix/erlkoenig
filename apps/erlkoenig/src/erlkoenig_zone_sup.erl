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

-module(erlkoenig_zone_sup).
-moduledoc """
Top-level supervisor for all network zones.

Reads zone definitions from erlkoenig_zone and creates a
rest_for_one child supervisor per zone, each containing
ip_pool and dns services. Link creation (IPVLAN slave into
container netns) is driven on-demand per container via
erlkoenig_zone_link_ipvlan — no persistent link process.

Architecture:
  erlkoenig_zone_sup (one_for_one)
    +-- zone_default_sup (rest_for_one)
    |     +-- erlkoenig_ip_pool (for zone default)
    |     +-- erlkoenig_dns (for zone default)
    +-- zone_dmz_sup (rest_for_one)
    |     +-- erlkoenig_ip_pool (for zone dmz)
    |     +-- erlkoenig_dns (for zone dmz)
    ...
""".

-behaviour(supervisor).

-export([start_link/0, start_zone/1, stop_zone/1, init/1]).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, top).

-doc "Dynamically start a new zone supervisor tree.".
-spec start_zone(atom()) -> {ok, pid()} | {error, term()}.
start_zone(ZoneName) ->
    ChildSpec = zone_child_spec(ZoneName),
    supervisor:start_child(?MODULE, ChildSpec).

-doc "Stop and remove a zone supervisor tree.".
-spec stop_zone(atom()) -> ok | {error, term()}.
stop_zone(ZoneName) ->
    ChildId = {zone_sup, ZoneName},
    case supervisor:terminate_child(?MODULE, ChildId) of
        ok    -> supervisor:delete_child(?MODULE, ChildId);
        Error -> Error
    end.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%% Top-level: one child supervisor per zone.
init(top) ->
    Zones = erlkoenig_zone:zones(),
    Children = [zone_child_spec(ZoneName) || ZoneName <- Zones],
    {ok, {#{strategy => one_for_one,
             intensity => 5,
             period => 30}, Children}};

%% Per-zone: ip_pool -> dns (rest_for_one ordering).
%% IPVLAN-only (ADR-0020): no bridge child.
init({zone, ZoneName, Config}) ->
    CommonChildren = [
        #{id       => {erlkoenig_ip_pool, ZoneName},
          start    => {erlkoenig_ip_pool, start_link, [Config]},
          restart  => permanent,
          type     => worker,
          shutdown => 5000},
        #{id       => {erlkoenig_dns, ZoneName},
          start    => {erlkoenig_dns, start_link, [Config]},
          restart  => permanent,
          type     => worker,
          shutdown => 5000}
    ],
    {ok, {#{strategy => rest_for_one,
             intensity => 3,
             period => 10}, CommonChildren}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

zone_child_spec(ZoneName) ->
    Config = maps:put(zone, ZoneName, erlkoenig_zone:zone_config(ZoneName)),
    #{id       => {zone_sup, ZoneName},
      start    => {supervisor, start_link, [?MODULE, {zone, ZoneName, Config}]},
      restart  => permanent,
      type     => supervisor,
      shutdown => infinity}.
