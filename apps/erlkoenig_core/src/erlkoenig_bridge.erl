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
%% @doc Bridge lifecycle manager.
%%
%% Creates the erlkoenig bridge at startup and tears it down on
%% termination. Holds the bridge interface index in state so
%% other modules don't need to look it up repeatedly.
%%
%% NAT/forwarding is out of scope for Phase 3. Containers can
%% reach each other and the host via the bridge, but not the
%% outside world yet.
%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_bridge).

-behaviour(gen_server).

-export([start_link/0, start_link/1,
         ifindex/0, ifindex/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    sock    :: socket:socket(),
    name    :: binary(),
    zone    :: atom(),
    ifindex :: non_neg_integer()
}).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Start with legacy config (single default zone).
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, legacy, []).

%% @doc Start with zone config map.
-spec start_link(map()) -> gen_server:start_ret().
start_link(Config) ->
    gen_server:start_link(?MODULE, {zone, Config}, []).

%% @doc Get the bridge interface index (default zone).
-spec ifindex() -> non_neg_integer().
ifindex() ->
    gen_server:call(?MODULE, ifindex).

%% @doc Get the bridge interface index for a specific zone.
-spec ifindex(atom()) -> non_neg_integer().
ifindex(default) ->
    %% Try registered name first (backward compat), then zone registry
    case whereis(?MODULE) of
        undefined ->
            Pid = erlkoenig_zone:bridge(default),
            gen_server:call(Pid, ifindex);
        Pid ->
            gen_server:call(Pid, ifindex)
    end;
ifindex(ZoneName) ->
    Pid = erlkoenig_zone:bridge(ZoneName),
    gen_server:call(Pid, ifindex).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init(legacy) ->
    Bridge = application:get_env(erlkoenig_core, bridge_name, <<"erlkoenig_br0">>),
    Gateway = application:get_env(erlkoenig_core, gateway, {10, 0, 0, 1}),
    Netmask = application:get_env(erlkoenig_core, netmask, 24),
    do_init(default, Bridge, Gateway, Netmask);

init({zone, #{zone := ZoneName, bridge := Bridge, gateway := Gateway,
              netmask := Netmask} = _Config}) ->
    do_init(ZoneName, Bridge, Gateway, Netmask).

do_init(ZoneName, Bridge, Gateway, Netmask) ->
    {ok, Sock} = erlkoenig_netlink:open(),
    case create_bridge(Sock, Bridge, Gateway, Netmask) of
        {ok, Idx} ->
            process_flag(trap_exit, true),
            register_zone_service(ZoneName),
            {ok, #state{sock = Sock, name = Bridge, zone = ZoneName, ifindex = Idx}};
        {error, Reason} ->
            erlkoenig_netlink:close(Sock),
            {stop, {bridge_setup_failed, Reason}}
    end.

register_zone_service(ZoneName) ->
    try erlkoenig_zone:register_service(ZoneName, bridge, self())
    catch _:_ -> ok
    end.

handle_call(ifindex, _From, #state{ifindex = Idx} = S) ->
    {reply, Idx, S}.

handle_cast(_Msg, S) ->
    {noreply, S}.

handle_info(_Msg, S) ->
    {noreply, S}.

terminate(_Reason, #state{sock = Sock, name = Bridge}) ->
    case get_ifindex(Sock, Bridge) of
        {ok, Idx} ->
            Seq = erlkoenig_netlink:next_seq(),
            _ = erlkoenig_netlink:request(
                  Sock, erlkoenig_netlink:msg_delete_link(Seq, Idx)),
            ok;
        _ ->
            ok
    end,
    erlkoenig_netlink:close(Sock),
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

-spec create_bridge(socket:socket(), binary(), inet:ip4_address(),
                    non_neg_integer()) -> {ok, non_neg_integer()} | {error, term()}.
create_bridge(Sock, Bridge, Gateway, Netmask) ->
    case get_ifindex(Sock, Bridge) of
        {ok, Idx} ->
            Seq = erlkoenig_netlink:next_seq(),
            _ = erlkoenig_netlink:request(
                  Sock, erlkoenig_netlink:msg_set_up(Seq, Idx)),
            {ok, Idx};
        {error, _} ->
            Seq1 = erlkoenig_netlink:next_seq(),
            case erlkoenig_netlink:request(
                   Sock, erlkoenig_netlink:msg_create_bridge(Seq1, Bridge)) of
                ok ->
                    {ok, Idx} = get_ifindex(Sock, Bridge),

                    Seq2 = erlkoenig_netlink:next_seq(),
                    ok = erlkoenig_netlink:request(
                           Sock, erlkoenig_netlink:msg_add_addr(
                                   Seq2, Idx, Gateway, Netmask)),

                    Seq3 = erlkoenig_netlink:next_seq(),
                    ok = erlkoenig_netlink:request(
                           Sock, erlkoenig_netlink:msg_set_up(Seq3, Idx)),

                    {ok, Idx};
                {error, _} = Err ->
                    Err
            end
    end.

-spec get_ifindex(socket:socket(), binary()) -> {ok, integer()} | {error, term()}.
get_ifindex(Sock, Name) ->
    Seq = erlkoenig_netlink:next_seq(),
    Msg = erlkoenig_netlink:msg_get_link(Seq, Name),
    case socket:send(Sock, Msg) of
        ok    -> erlkoenig_netlink:recv_ifindex(Sock);
        Error -> Error
    end.
