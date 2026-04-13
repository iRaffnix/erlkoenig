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

-module(erlkoenig_zone_link).
-moduledoc """
Zone-level container link management (IPVLAN L3S).

Thin wrapper around erlkoenig_zone_link_ipvlan.
Creates IPVLAN slaves for containers, manages parent devices.

ADR-0020: IPVLAN L3S is the only networking mode.
""".

-export([init/1, attach_container/2, detach_container/2]).
-export_type([link_ref/0]).

-type link_ref() :: map().

-spec init(map()) -> {ok, link_ref()} | {error, term()}.
init(Config) ->
    erlkoenig_zone_link_ipvlan:init(Config).

-spec attach_container(link_ref(), {binary(), non_neg_integer()}) ->
    {ok, map()} | {error, term()}.
attach_container(State, {SlaveName, OsPid}) ->
    erlkoenig_zone_link_ipvlan:attach_container(State, SlaveName, OsPid).

-spec detach_container(link_ref(), map()) -> ok.
detach_container(State, AttachInfo) ->
    erlkoenig_zone_link_ipvlan:detach_container(State, AttachInfo).
