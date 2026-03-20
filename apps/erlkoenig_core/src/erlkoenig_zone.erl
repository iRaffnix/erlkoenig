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

-module(erlkoenig_zone).
-moduledoc """
Zone registry and configuration manager.

Reads zone definitions from application env and stores them in
an ETS table together with service PIDs (bridge, ip_pool, dns).

If no {zones, ...} key is set, a single `default' zone is built
from the legacy keys bridge_name, subnet, gateway, netmask.

This module is purely a registry -- supervision lives in
erlkoenig_zone_sup.
""".

-behaviour(gen_server).

-export([start_link/0,
         zones/0,
         zone_config/1,
         register_service/3,
         bridge/1,
         ip_pool/1,
         dns/1,
         default_zone/0,
         create/2,
         destroy/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(TAB, erlkoenig_zones).

-type zone_name()   :: atom().
-type zone_config() :: #{bridge  := binary(),
                         subnet  := inet:ip4_address(),
                         gateway := inet:ip4_address(),
                         netmask := 0..32,
                         policy  := allow_outbound | isolate | strict}.
-type service_type() :: bridge | ip_pool | dns.

-export_type([zone_name/0, zone_config/0, service_type/0]).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc "Return the list of configured zone names.".
-spec zones() -> [zone_name()].
zones() ->
    [Name || {Name, Cfg} <- ets:tab2list(?TAB), is_atom(Name), is_map(Cfg)].

-doc "Get the config map for a zone. Crashes on unknown zone.".
-spec zone_config(zone_name()) -> zone_config().
zone_config(Zone) when is_atom(Zone) ->
    case ets:lookup(?TAB, Zone) of
        [{Zone, Cfg}] when is_map(Cfg) -> Cfg;
        _                              -> error({unknown_zone, Zone})
    end.

-doc "Register a service PID for a zone.".
-spec register_service(zone_name(), service_type(), pid()) -> ok.
register_service(Zone, Type, Pid) when is_atom(Zone), is_atom(Type), is_pid(Pid) ->
    gen_server:call(?MODULE, {register_service, Zone, Type, Pid}).

-doc "Look up the bridge PID for a zone. Crashes if not registered.".
-spec bridge(zone_name()) -> pid().
bridge(Zone) ->
    lookup_service_or_crash(Zone, bridge).

-doc "Look up the IP pool PID for a zone. Crashes if not registered.".
-spec ip_pool(zone_name()) -> pid().
ip_pool(Zone) ->
    lookup_service_or_crash(Zone, ip_pool).

-doc "Look up the DNS PID for a zone. Crashes if not registered.".
-spec dns(zone_name()) -> pid().
dns(Zone) ->
    lookup_service_or_crash(Zone, dns).

-doc "Return the name of the default zone.".
-spec default_zone() -> zone_name().
default_zone() ->
    default.

-doc "Create a new zone at runtime. Starts bridge, ip_pool, dns.".
-spec create(zone_name(), zone_config()) -> ok | {error, term()}.
create(Name, Config) when is_atom(Name), is_map(Config) ->
    gen_server:call(?MODULE, {create_zone, Name, normalize_config(Config)}, 15000).

-doc "Destroy a zone. Fails if containers are still using it.".
-spec destroy(zone_name()) -> ok | {error, term()}.
destroy(Name) when is_atom(Name) ->
    gen_server:call(?MODULE, {destroy_zone, Name}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    proc_lib:set_label(erlkoenig_zone),
    ?TAB = ets:new(?TAB, [set, named_table, public, {read_concurrency, true}]),
    Zones = load_zones(),
    lists:foreach(fun({Name, Cfg}) ->
        true = ets:insert(?TAB, {Name, Cfg})
    end, Zones),
    {ok, #{}}.

handle_call({register_service, Zone, Type, Pid}, _From, State) ->
    case ets:lookup(?TAB, Zone) of
        [{Zone, Cfg}] when is_map(Cfg) ->
            true = ets:insert(?TAB, {{Zone, Type}, Pid}),
            {reply, ok, State};
        _ ->
            {reply, {error, unknown_zone}, State}
    end;

handle_call({create_zone, Name, Cfg}, From, State) ->
    case ets:lookup(?TAB, Name) of
        [{Name, _}] ->
            {reply, {error, already_exists}, State};
        _ ->
            true = ets:insert(?TAB, {Name, Cfg}),
            %% Start zone supervisor asynchronously to avoid deadlock:
            %% bridge init calls register_service back into this gen_server.
            spawn_link(fun() ->
                Result = case erlkoenig_zone_sup:start_zone(Name) of
                    {ok, _Pid} ->
                        logger:info("zone ~s created: ~s/~b on ~s",
                                    [Name,
                                     inet:ntoa(maps:get(subnet, Cfg)),
                                     maps:get(netmask, Cfg),
                                     maps:get(bridge, Cfg)]),
                        ok;
                    {error, _} = Err ->
                        true = ets:delete(?TAB, Name),
                        Err
                end,
                gen_server:reply(From, Result)
            end),
            {noreply, State}
    end;

handle_call({destroy_zone, Name}, _From, State) ->
    case Name of
        default ->
            {reply, {error, cannot_destroy_default}, State};
        _ ->
            case zone_has_containers(Name) of
                true ->
                    {reply, {error, zone_not_empty}, State};
                false ->
                    case erlkoenig_zone_sup:stop_zone(Name) of
                        ok ->
                            ets:delete(?TAB, {Name, bridge}),
                            ets:delete(?TAB, {Name, ip_pool}),
                            ets:delete(?TAB, {Name, dns}),
                            ets:delete(?TAB, Name),
                            logger:info("zone ~s destroyed", [Name]),
                            {reply, ok, State};
                        {error, _} = Err ->
                            {reply, Err, State}
                    end
            end
    end;

handle_call(_Msg, _From, State) ->
    {reply, {error, bad_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

-doc "Load zone configs from app env. Falls back to legacy keys.".
-spec load_zones() -> [{zone_name(), zone_config()}].
load_zones() ->
    case application:get_env(erlkoenig_core, zones) of
        {ok, ZoneList} when is_list(ZoneList) ->
            [{Name, normalize_config(Cfg)} || {Name, Cfg} <- ZoneList];
        _ ->
            [build_default_zone()]
    end.

-doc "Build a single default zone from legacy flat config keys.".
-spec build_default_zone() -> {zone_name(), zone_config()}.
build_default_zone() ->
    Bridge  = application:get_env(erlkoenig_core, bridge_name, <<"erlkoenig_br0">>),
    Subnet  = application:get_env(erlkoenig_core, subnet,  {10, 0, 0, 0}),
    Gateway = application:get_env(erlkoenig_core, gateway, {10, 0, 0, 1}),
    Netmask = application:get_env(erlkoenig_core, netmask, 24),
    Cfg = #{bridge  => Bridge,
            subnet  => Subnet,
            gateway => Gateway,
            netmask => Netmask,
            policy  => allow_outbound},
    {default, Cfg}.

-doc "Ensure all required keys are present, fill in defaults.".
-spec normalize_config(map()) -> zone_config().
normalize_config(Cfg) when is_map(Cfg) ->
    #{bridge  => maps:get(bridge,  Cfg, <<"erlkoenig_br0">>),
      subnet  => maps:get(subnet,  Cfg, {10, 0, 0, 0}),
      gateway => maps:get(gateway, Cfg, {10, 0, 0, 1}),
      netmask => maps:get(netmask, Cfg, 24),
      policy  => maps:get(policy,  Cfg, allow_outbound)}.

-doc "Look up a service PID by zone + type. Returns {ok, Pid} or error.".
-spec lookup_service(zone_name(), service_type()) -> {ok, pid()} | {error, not_registered}.
lookup_service(Zone, Type) ->
    case ets:lookup(?TAB, {Zone, Type}) of
        [{{Zone, Type}, Pid}] -> {ok, Pid};
        _                     -> {error, not_registered}
    end.

-spec lookup_service_or_crash(zone_name(), service_type()) -> pid().
lookup_service_or_crash(Zone, Type) ->
    case lookup_service(Zone, Type) of
        {ok, Pid} -> Pid;
        {error, _} -> error({zone_service_not_registered, Zone, Type})
    end.

-doc "Check if any running container belongs to this zone.".
-spec zone_has_containers(zone_name()) -> boolean().
zone_has_containers(Zone) ->
    lists:any(fun(Info) ->
        maps:get(zone, Info, default) =:= Zone
    end, erlkoenig_core:list()).
