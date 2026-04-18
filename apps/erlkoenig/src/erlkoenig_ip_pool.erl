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

Manages an IPv4 subnet of arbitrary prefix between /16 and /30,
handing out host addresses skipping the network address (`.0` of the
range), the gateway (`.1` of the range), and the broadcast address
(last). Released addresses are recycled (free-list).

All access is serialized through the gen_server to avoid races.
""".

-behaviour(gen_server).

-export([start_link/0, start_link/1,
         allocate/0, allocate/1,
         release/1,
         used_count/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

%% Pool boundaries are 32-bit absolute integers in network order.
%% First = network base + 2  (skip .0 = network, .1 = gateway).
%% Last  = broadcast - 1     (skip the broadcast).
%% Cursor `next' walks First → Last; `free' is a recycle list of
%% absolute integers between First and Last.
-record(state, {
    zone    :: atom(),
    subnet  :: {byte(), byte(), byte(), byte()},
    netmask :: 16..30,
    first   :: non_neg_integer(),
    last    :: non_neg_integer(),
    next    :: non_neg_integer(),
    free    :: [non_neg_integer()]
}).

%%%===================================================================
%%% API
%%%===================================================================

-doc "Start with legacy config (single default zone, /24).".
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
    Subnet  = application:get_env(erlkoenig, subnet, {10, 0, 0, 0}),
    Netmask = application:get_env(erlkoenig, netmask, 24),
    register_zone_service(default),
    init_state(default, Subnet, Netmask);

init({zone, #{zone := ZoneName, network := Net} = _Config}) ->
    proc_lib:set_label({erlkoenig_ip_pool, ZoneName}),
    Subnet  = maps:get(subnet,  Net, {10, 0, 0, 0}),
    Netmask = maps:get(netmask, Net, 24),
    register_zone_service(ZoneName),
    init_state(ZoneName, Subnet, Netmask);
%% Legacy: flat config
init({zone, #{zone := ZoneName, subnet := Subnet} = Cfg}) ->
    proc_lib:set_label({erlkoenig_ip_pool, ZoneName}),
    Netmask = maps:get(netmask, Cfg, 24),
    register_zone_service(ZoneName),
    init_state(ZoneName, Subnet, Netmask).

%% Build the pool state or return {stop, Reason} so start_link surfaces
%% a clean `{error, Reason}' instead of an Erlang crash report.
init_state(ZoneName, Subnet, Netmask) ->
    try
        {ok, build_state(ZoneName, Subnet, Netmask)}
    catch error:{unsupported_netmask, _, _, _} = Reason ->
        {stop, Reason}
    end.

%% Compute the absolute First/Last integers for the pool given
%% the configured subnet and prefix. Reject prefixes outside the
%% supported range so the operator gets a clear error at boot.
-spec build_state(atom(), inet:ip4_address(), 16..30) -> #state{}.
build_state(_ZoneName, _Subnet, Netmask)
  when not (is_integer(Netmask) andalso Netmask >= 16
            andalso Netmask =< 30) ->
    error({unsupported_netmask, Netmask, supported, {16, 30}});
build_state(ZoneName, {A, B, C, D}, Netmask) ->
    Base32 = ((A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D)
             band mask_for(Netmask),
    Bcast = Base32 bor host_mask(Netmask),
    First = Base32 + 2,           %% skip network + gateway
    Last  = Bcast - 1,            %% skip broadcast
    {NA, NB, NC, _} = u32_to_ip(Base32),
    #state{zone = ZoneName,
           subnet = {NA, NB, NC, 0},
           netmask = Netmask,
           first = First,
           last  = Last,
           next  = First,
           free  = []}.

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
find_pool_for_ip({A, B, C, D} = Ip, [Zone | Rest]) ->
    case erlkoenig_zone:zone_config(Zone) of
        #{network := #{subnet := SubnetIp, netmask := Mask}}
          when is_integer(Mask) ->
            case ip_in_subnet({A, B, C, D}, SubnetIp, Mask) of
                true  -> {ok, erlkoenig_zone:ip_pool(Zone)};
                false -> find_pool_for_ip(Ip, Rest)
            end;
        #{subnet := {A, B, C, _}} ->
            %% Legacy /24 match
            {ok, erlkoenig_zone:ip_pool(Zone)};
        _ ->
            find_pool_for_ip(Ip, Rest)
    end.

handle_call(allocate, _From, #state{free = [H | T]} = S) ->
    {reply, {ok, u32_to_ip(H)}, S#state{free = T}};
handle_call(allocate, _From, #state{next = N, last = L} = S) when N > L ->
    {reply, {error, exhausted}, S};
handle_call(allocate, _From, #state{next = N} = S) ->
    {reply, {ok, u32_to_ip(N)}, S#state{next = N + 1}};

handle_call(used_count, _From, #state{next = N, first = First,
                                       free = Free} = S) ->
    %% Allocated = (N - First) total handed out, minus recycled
    {reply, (N - First) - length(Free), S}.

handle_cast({release, {A, B, C, D}},
            #state{first = First, last = Last, free = Free} = S) ->
    Abs = (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D,
    case Abs >= First andalso Abs =< Last andalso
         not lists:member(Abs, Free) of
        true  -> {noreply, S#state{free = [Abs | Free]}};
        false -> {noreply, S}
    end.

handle_info(_Msg, S) ->
    {noreply, S}.

%%%===================================================================
%%% Internal helpers
%%%===================================================================

%% Network mask: the high `Prefix' bits set, the rest cleared.
-spec mask_for(16..30) -> non_neg_integer().
mask_for(Prefix) ->
    (16#FFFFFFFF bsl (32 - Prefix)) band 16#FFFFFFFF.

%% Host mask: the low `(32 - Prefix)' bits set.
-spec host_mask(16..30) -> non_neg_integer().
host_mask(Prefix) ->
    (1 bsl (32 - Prefix)) - 1.

-spec u32_to_ip(non_neg_integer()) -> inet:ip4_address().
u32_to_ip(N) ->
    {(N bsr 24) band 16#FF, (N bsr 16) band 16#FF,
     (N bsr  8) band 16#FF,  N         band 16#FF}.

-spec ip_in_subnet(inet:ip4_address(), inet:ip4_address(), 16..30) ->
    boolean().
ip_in_subnet({A1, B1, C1, D1}, {A2, B2, C2, D2}, Prefix) ->
    Ip   = (A1 bsl 24) bor (B1 bsl 16) bor (C1 bsl 8) bor D1,
    Sub  = (A2 bsl 24) bor (B2 bsl 16) bor (C2 bsl 8) bor D2,
    Mask = mask_for(Prefix),
    (Ip band Mask) =:= (Sub band Mask).
