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

High-level module that sets up networking for containers:
  1. Per container: veth pair, move into netns, attach to bridge
  2. In-netns config: IP, up, route -- via CMD_NET_SETUP to erlkoenig_rt
  3. Teardown: delete host veth (peer disappears automatically)

Host-side operations use erlkoenig_netlink (pure Erlang netlink).
In-netns operations are delegated to erlkoenig_rt via the port
protocol, which uses setns() + C netlink internally.

Network topology:

  Host namespace                Container namespace
  +-----------+                 +-----------+
  | erlkoenig   |                 | eth0      |
  | _br0      |---veth_XXXX----| 10.0.0.X  |
  | 10.0.0.1  |                 +-----------+
  +-----------+
""".

-export([setup_container_net/3,
         setup_container_net/4,
         setup_container_net/5,
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
ContainerId: UUID binary (used to derive veth name)
OsPid:       Linux PID of the container process (in host pidns)

Steps:
  1. Allocate an IP from the pool
  2. Create veth pair (host: veth_XXXX, container: eth0)
  3. Move eth0 into the container's network namespace
  4. Attach veth_XXXX to the bridge
  5. Bring veth_XXXX up (host side)
  6. Send CMD_NET_SETUP to erlkoenig_rt (configures eth0 inside netns)

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
    HostVeth = host_veth_name(ContainerId),
    ContainerVeth = peer_veth_name(ContainerId),
    maybe
        ok ?= do_host_setup(HostVeth, ContainerVeth, OsPid, ZoneName),
        Gateway = zone_gateway(ZoneName),
        Mask = zone_netmask(ZoneName),
        ok ?= do_netns_setup(Port, ContainerVeth, Ip, Gateway, Mask),
        {ok, #{host_veth => HostVeth,
               container_veth => ContainerVeth,
               ip => Ip,
               gateway => Gateway,
               netmask => Mask,
               zone => ZoneName}}
    else
        {error, _} = Err ->
            _ = rollback_veth(HostVeth),
            Err
    end.

-doc "Tear down a container's network (veth + IP release). Deleting the host veth automatically deletes the peer.".
-spec teardown_container_net(map()) -> ok.
teardown_container_net(#{host_veth := HostVeth, ip := Ip}) ->
    _ = rollback_veth(HostVeth),
    erlkoenig_ip_pool:release(Ip),
    ok;
teardown_container_net(_) ->
    ok.

-doc """
Tear down only the veth pair, keep the IP reserved.

Used during container restart: the veth is deleted (network goes
down), but the IP stays allocated so the container keeps the same
address after restart.
""".
-spec teardown_container_veth(map()) -> ok.
teardown_container_veth(#{host_veth := HostVeth}) ->
    _ = rollback_veth(HostVeth),
    ok;
teardown_container_veth(_) ->
    ok.

%%%===================================================================
%%% Internal: Host-side setup (pure netlink)
%%%===================================================================

-spec do_host_setup(binary(), binary(), non_neg_integer(), atom()) -> ok | {error, term()}.
do_host_setup(HostVeth, ContainerVeth, OsPid, ZoneName) ->
    {ok, Sock} = erlkoenig_netlink:open(),
    try
        do_host_setup_veth(Sock, HostVeth, ContainerVeth, OsPid, ZoneName)
    after
        erlkoenig_netlink:close(Sock)
    end.

%% Step 1: Create veth pair.
-spec do_host_setup_veth(socket:socket(), binary(), binary(),
                         non_neg_integer(), atom()) -> ok | {error, term()}.
do_host_setup_veth(Sock, HostVeth, ContainerVeth, OsPid, ZoneName) ->
    maybe
        Seq = erlkoenig_netlink:next_seq(),
        ok ?= erlkoenig_netlink:request(
                Sock, erlkoenig_netlink:msg_create_veth(Seq, HostVeth, ContainerVeth)),
        %% Step 2: Move container end into container's netns.
        {ok, PeerIdx} ?= get_ifindex(Sock, ContainerVeth),
        Seq2 = erlkoenig_netlink:next_seq(),
        ok ?= erlkoenig_netlink:request(
                Sock, erlkoenig_netlink:msg_set_netns_by_pid(Seq2, PeerIdx, OsPid)),
        %% Step 3: Attach host end to bridge, bring up.
        BridgeIdx = erlkoenig_bridge:ifindex(ZoneName),
        {ok, HostIdx} ?= get_ifindex(Sock, HostVeth),
        Seq3 = erlkoenig_netlink:next_seq(),
        ok ?= erlkoenig_netlink:request(
                Sock, erlkoenig_netlink:msg_set_master(Seq3, HostIdx, BridgeIdx)),
        %% Step 4: Bring host end up
        Seq4 = erlkoenig_netlink:next_seq(),
        ok ?= erlkoenig_netlink:request(
                Sock, erlkoenig_netlink:msg_set_up(Seq4, HostIdx))
    else
        {error, _} = Err ->
            _ = delete_link(Sock, HostVeth),
            Err
    end.

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

-spec get_ifindex(socket:socket(), binary()) -> {ok, integer()} | {error, term()}.
get_ifindex(Sock, Name) ->
    Seq = erlkoenig_netlink:next_seq(),
    Msg = erlkoenig_netlink:msg_get_link(Seq, Name),
    case socket:send(Sock, Msg) of
        ok    -> erlkoenig_netlink:recv_ifindex(Sock);
        Error -> Error
    end.

-spec delete_link(socket:socket(), binary()) -> ok | {error, term()}.
delete_link(Sock, Name) ->
    case get_ifindex(Sock, Name) of
        {ok, Idx} ->
            Seq = erlkoenig_netlink:next_seq(),
            erlkoenig_netlink:request(
              Sock, erlkoenig_netlink:msg_delete_link(Seq, Idx));
        _ ->
            ok
    end.

-spec rollback_veth(binary()) -> ok | {error, term()}.
rollback_veth(HostVeth) ->
    {ok, Sock} = erlkoenig_netlink:open(),
    try
        delete_link(Sock, HostVeth)
    after
        erlkoenig_netlink:close(Sock)
    end.

%% Generate veth names from container ID.
%% IFNAMSIZ is 16 (including NUL), so max 15 chars.
%% Host:  "vh_" (3) + 12 chars = 15
%% Peer:  "vp_" (3) + 12 chars = 15
%% The peer name is temporary -- it keeps this name inside the netns.
-spec host_veth_name(binary()) -> binary().
host_veth_name(ContainerId) ->
    Short = binary:part(ContainerId, 0, min(12, byte_size(ContainerId))),
    <<"vh_", Short/binary>>.

-spec peer_veth_name(binary()) -> binary().
peer_veth_name(ContainerId) ->
    Short = binary:part(ContainerId, 0, min(12, byte_size(ContainerId))),
    <<"vp_", Short/binary>>.

-spec zone_gateway(atom()) -> inet:ip4_address().
zone_gateway(default) ->
    application:get_env(erlkoenig_core, gateway, {10, 0, 0, 1});
zone_gateway(ZoneName) ->
    #{gateway := Gw} = erlkoenig_zone:zone_config(ZoneName),
    Gw.

-spec zone_netmask(atom()) -> non_neg_integer().
zone_netmask(default) ->
    application:get_env(erlkoenig_core, netmask, 24);
zone_netmask(ZoneName) ->
    #{netmask := Nm} = erlkoenig_zone:zone_config(ZoneName),
    Nm.
