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

-module(erlkoenig_net).
-moduledoc """
Container network orchestration.

Thin dispatcher that delegates link creation to the zone_link
behaviour (IPVLAN L3S), then sends CMD_NET_SETUP to the C
runtime for in-netns IP/route configuration.

IPVLAN L3S mode (the only mode since ADR-0020):

    Host namespace                Container namespace
    +-----------+                 +-----------+
    | eth0/     |     (no host    | i.name    |
    | ek_ct0    |      side)      | 10.X.X.X  |
    +-----------+                 +-----------+

Slave created directly in the container netns by
erlkoenig_zone_link_ipvlan (via IFLA_NET_NS_PID). Parent is
either a physical device (`{:device, "eth0"}`) or a dummy
owned by erlkoenig (`{:dummy, "ek_ct0"}`).

CMD_NET_SETUP configures IP/route/UP inside the container's
netns. The C runtime is link-agnostic.
""".

-export([setup_container_net/3,
         setup_container_net/4,
         setup_container_net/5,
         setup_container_net/6,
         teardown_container_net/1,
         teardown_container_veth/1]).

%% setup_container_net/3 — allocate from default zone (legacy)
%% setup_container_net/4 — (Port, Id, OsPid, Zone) allocate from zone
%%                       — (Port, Id, OsPid, Ip)   explicit IP, default zone
%% setup_container_net/5 — explicit IP + zone

%%%===================================================================
%%% Per-Container Network Setup
%%%===================================================================

-doc """
Set up networking for a container.

Port:        Erlang port to the erlkoenig_rt process (for CMD_NET_SETUP)
ContainerId: UUID binary (used to derive the slave's interface name)
OsPid:       Linux PID of the container process (in host pidns)

Steps:
  1. Allocate an IP from the zone's pool
  2. Ask erlkoenig_zone_link_ipvlan to create an IPVLAN L3S slave
     directly in the container's netns (IFLA_NET_NS_PID)
  3. Send CMD_NET_SETUP to erlkoenig_rt (configures address, route
     and UP inside the netns)

Returns a NetInfo map needed for teardown.
""".
-type rt_handle() :: port() | {socket, gen_tcp:socket()}.

-spec setup_container_net(rt_handle(), binary(), non_neg_integer()) ->
    {ok, map()} | {error, term()}.
setup_container_net(Port, ContainerId, OsPid) ->
    setup_container_net(Port, ContainerId, OsPid, default).

-doc "Set up networking: allocate IP from a named zone, or use an explicit IP in the default zone.".
-spec setup_container_net(rt_handle(), binary(), non_neg_integer(),
                          inet:ip4_address() | atom()) ->
    {ok, map()} | {error, term()}.
setup_container_net(Port, ContainerId, OsPid, ZoneName) when is_atom(ZoneName) ->
    case erlkoenig_ip_pool:allocate(ZoneName) of
        {error, _} = Err -> Err;
        {ok, Ip}         -> setup_container_net(Port, ContainerId, OsPid, Ip, ZoneName)
    end;
setup_container_net(Port, ContainerId, OsPid, Ip) ->
    setup_container_net(Port, ContainerId, OsPid, Ip, default).

-doc "Set up networking with an explicit IP in a specific zone.".
-spec setup_container_net(rt_handle(), binary(), non_neg_integer(),
                          inet:ip4_address(), atom()) ->
    {ok, map()} | {error, term()}.
setup_container_net(Port, ContainerId, OsPid, Ip, ZoneName) ->
    setup_container_net(Port, ContainerId, OsPid, Ip, ZoneName, undefined).

-doc "Set up networking with an explicit IP, zone, and container name.".
-spec setup_container_net(rt_handle(), binary(), non_neg_integer(),
                          inet:ip4_address(), atom(), binary() | undefined) ->
    {ok, map()} | {error, term()}.
setup_container_net(Port, ContainerId, OsPid, Ip, ZoneName, Name) ->
    LinkRef = erlkoenig_zone:link_state(ZoneName),
    IfName = container_iface_name(ContainerId, Name, LinkRef),
    maybe
        {ok, AttachInfo} ?= erlkoenig_zone_link:attach_container(
                              LinkRef, {IfName, OsPid}),
        Gateway0 = zone_gateway(ZoneName),
        Gateway = case Gateway0 of
            undefined -> {0, 0, 0, 0};
            _         -> Gateway0
        end,
        Mask = zone_netmask(ZoneName),
        ok ?= do_netns_setup(Port, IfName, Ip, Gateway, Mask),
        {ok, #{ip => Ip,
               gateway => Gateway,
               netmask => Mask,
               zone => ZoneName,
               iface => IfName,
               attach => AttachInfo,
               %% Backward compat: existing code reads host_veth/container_veth
               host_veth => maps:get(host_veth, AttachInfo, undefined),
               container_veth => maps:get(peer_veth, AttachInfo, IfName)}}
    else
        {error, _} = Err ->
            _ = erlkoenig_zone_link:detach_container(LinkRef, #{slave => IfName}),
            Err
    end.

-doc "Tear down a container's network (link + IP release).".
-spec teardown_container_net(map()) -> ok.
teardown_container_net(#{ip := Ip, zone := ZoneName, attach := AttachInfo}) ->
    LinkRef = erlkoenig_zone:link_state(ZoneName),
    _ = erlkoenig_zone_link:detach_container(LinkRef, AttachInfo),
    erlkoenig_ip_pool:release(Ip),
    ok;
teardown_container_net(_) ->
    ok.

-doc """
Tear down only the link, keep the IP reserved.

Used during container restart: the link is removed (network goes
down), but the IP stays allocated so the container keeps the same
address after restart.
""".
-spec teardown_container_veth(map()) -> ok.
teardown_container_veth(#{zone := ZoneName, attach := AttachInfo}) ->
    LinkRef = erlkoenig_zone:link_state(ZoneName),
    _ = erlkoenig_zone_link:detach_container(LinkRef, AttachInfo),
    ok;
teardown_container_veth(_) ->
    ok.

%%%===================================================================
%%% Internal: In-netns setup (via erlkoenig_rt CMD_NET_SETUP)
%%%===================================================================

-spec do_netns_setup(port() | {socket, gen_tcp:socket()}, binary(),
                     inet:ip4_address(), inet:ip4_address(),
                     non_neg_integer()) -> ok | {error, term()}.
do_netns_setup({socket, Sock}, IfName, Ip, Gateway, Prefixlen) ->
    Cmd = erlkoenig_proto:encode_cmd_net_setup(IfName, Ip, Prefixlen, Gateway),
    ok = gen_tcp:send(Sock, Cmd),
    %% Socket must be in {active, false} for this to work
    case gen_tcp:recv(Sock, 0, 10000) of
        {ok, Reply} ->
            case erlkoenig_proto:decode(Reply) of
                {ok, reply_ok, _} ->
                    ok;
                {ok, reply_error, #{code := Code, message := Msg}} ->
                    {error, {net_setup_failed, Code, Msg}};
                Other ->
                    {error, {unexpected_reply, Other}}
            end;
        {error, timeout} ->
            {error, net_setup_timeout};
        {error, Reason} ->
            {error, {net_setup_socket_error, Reason}}
    end;
do_netns_setup(Port, IfName, Ip, Gateway, Prefixlen) when is_port(Port) ->
    Cmd = erlkoenig_proto:encode_cmd_net_setup(IfName, Ip, Prefixlen, Gateway),
    port_command(Port, Cmd),
    receive
        {Port, {data, Reply}} ->
            case erlkoenig_proto:decode(Reply) of
                {ok, reply_ok, _} ->
                    ok;
                {ok, reply_error, #{code := Code, message := Msg}} ->
                    {error, {net_setup_failed, Code, Msg}};
                Other ->
                    {error, {unexpected_reply, Other}}
            end
    after 10000 ->
        {error, net_setup_timeout}
    end.

%%%===================================================================
%%% Internal: Helpers
%%%===================================================================


%% IPVLAN slave names: "i." (2 bytes) + ≤13 byte short name = ≤15 (IFNAMSIZ-1).
-spec container_iface_name(binary(), binary() | undefined,
                           erlkoenig_zone_link:link_ref()) -> binary().
container_iface_name(ContainerId, Name, _LinkRef) ->
    ipvlan_name(ContainerId, Name).

-spec ipvlan_name(binary(), binary() | undefined) -> binary().
ipvlan_name(ContainerId, undefined) ->
    make_ifname(short_id(ContainerId));
ipvlan_name(_ContainerId, Name) ->
    make_ifname(short_name(Name)).

-spec make_ifname(binary()) -> binary().
make_ifname(Short) ->
    IfName = <<"i.", Short/binary>>,
    case byte_size(IfName) of
        N when N =< 15 -> IfName;
        N -> error({interface_name_too_long, IfName, N, max_15})
    end.

%% Short container identifier — at most 12 bytes to fit inside IFNAMSIZ.
short_id(Id) ->
    binary:part(Id, 0, min(12, byte_size(Id))).

%% Shorten name to fit in 12 chars: remove dashes, truncate.
%% "web-0-nginx" → "web0nginx" (9 chars)
%% "data-0-postgres" → "data0postgre" (12 chars)
short_name(Name) ->
    Compact = binary:replace(Name, <<"-">>, <<>>, [global]),
    binary:part(Compact, 0, min(12, byte_size(Compact))).

-spec zone_gateway(atom()) -> inet:ip4_address() | undefined.
zone_gateway(default) ->
    application:get_env(erlkoenig, gateway, {10, 0, 0, 1});
zone_gateway(ZoneName) ->
    #{network := Net} = erlkoenig_zone:zone_config(ZoneName),
    maps:get(gateway, Net, {10, 0, 0, 1}).

-spec zone_netmask(atom()) -> non_neg_integer().
zone_netmask(default) ->
    application:get_env(erlkoenig, netmask, 24);
zone_netmask(ZoneName) ->
    #{network := Net} = erlkoenig_zone:zone_config(ZoneName),
    maps:get(netmask, Net, 24).
