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

-module(erlkoenig_ip_pool).
-moduledoc """
IP address pool for container networking.

Manages a /24 subnet, handing out addresses .2 through .254.
Released addresses are recycled (free-list).

All access is serialized through the gen_server to avoid races.
""".

-behaviour(gen_server).

-export([start_link/0, start_link/1,
         allocate/0, allocate/1,
         release/1,
         used_count/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {
    zone    :: atom(),
    subnet  :: {byte(), byte(), byte(), byte()},
    next    :: 2..255,
    free    :: [byte()]
}).

%%%===================================================================
%%% API
%%%===================================================================

-doc "Start with legacy config (single default zone).".
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, legacy, []).

-doc "Start with zone config map.".
-spec start_link(map()) -> gen_server:start_ret().
start_link(Config) ->
    gen_server:start_link(?MODULE, {zone, Config}, []).

-doc "Allocate from the default zone.".
-spec allocate() -> {ok, inet:ip4_address()} | {error, exhausted}.
allocate() ->
    gen_server:call(?MODULE, allocate).

-doc "Allocate from a specific zone.".
-spec allocate(atom()) -> {ok, inet:ip4_address()} | {error, exhausted}.
allocate(ZoneName) ->
    Pid = erlkoenig_zone:ip_pool(ZoneName),
    gen_server:call(Pid, allocate).

-doc "Release an IP back to its zone's pool.".
-spec release(inet:ip4_address()) -> ok.
release(Ip) ->
    %% Find the right pool by subnet match, or use default
    case find_pool_for_ip(Ip) of
        {ok, Pid} -> gen_server:cast(Pid, {release, Ip});
        error     -> gen_server:cast(?MODULE, {release, Ip})
    end.

-doc "Return the number of currently allocated IPs (default zone).".
-spec used_count() -> non_neg_integer().
used_count() ->
    gen_server:call(?MODULE, used_count).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init(legacy) ->
    proc_lib:set_label({erlkoenig_ip_pool, default}),
    {A, B, C, _} = application:get_env(erlkoenig_core, subnet, {10, 0, 0, 0}),
    register_zone_service(default),
    {ok, #state{zone = default, subnet = {A, B, C, 0}, next = 2, free = []}};

init({zone, #{zone := ZoneName, subnet := {A, B, C, _}} = _Config}) ->
    proc_lib:set_label({erlkoenig_ip_pool, ZoneName}),
    register_zone_service(ZoneName),
    {ok, #state{zone = ZoneName, subnet = {A, B, C, 0}, next = 2, free = []}}.

register_zone_service(ZoneName) ->
    try erlkoenig_zone:register_service(ZoneName, ip_pool, self())
    catch _:_ -> ok
    end.

find_pool_for_ip(Ip) ->
    try
        Zones = erlkoenig_zone:zones(),
        find_pool_for_ip(Ip, Zones)
    catch _:_ -> error
    end.

find_pool_for_ip(_Ip, []) -> error;
find_pool_for_ip({A, B, C, _} = _Ip, [Zone | Rest]) ->
    case erlkoenig_zone:zone_config(Zone) of
        #{subnet := {A, B, C, _}} ->
            {ok, erlkoenig_zone:ip_pool(Zone)};
        _ ->
            find_pool_for_ip(_Ip, Rest)
    end.

handle_call(allocate, _From, #state{free = [H | T]} = S) ->
    {A, B, C, _} = S#state.subnet,
    {reply, {ok, {A, B, C, H}}, S#state{free = T}};
handle_call(allocate, _From, #state{next = N} = S) when N > 254 ->
    {reply, {error, exhausted}, S};
handle_call(allocate, _From, #state{next = N} = S) ->
    {A, B, C, _} = S#state.subnet,
    {reply, {ok, {A, B, C, N}}, S#state{next = N + 1}};

handle_call(used_count, _From, #state{next = N, free = Free} = S) ->
    %% Allocated = (N - 2) total handed out, minus recycled
    {reply, (N - 2) - length(Free), S}.

handle_cast({release, {_, _, _, D}}, #state{free = Free} = S) ->
    case lists:member(D, Free) of
        true  -> {noreply, S};
        false -> {noreply, S#state{free = [D | Free]}}
    end.

handle_info(_Msg, S) ->
    {noreply, S}.
