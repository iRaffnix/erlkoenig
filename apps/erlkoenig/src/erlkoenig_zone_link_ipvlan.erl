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

-module(erlkoenig_zone_link_ipvlan).
-moduledoc """
IPVLAN L3S implementation of erlkoenig_zone_link.

Creates an IPVLAN slave directly in the container's network namespace
via IFLA_NET_NS_PID at creation time (single netlink call, no move).

Detach is a no-op: the slave lives in the container's netns and is
automatically destroyed by the kernel when the netns is removed
(container process exit). Erlang cannot delete the slave because it
would require setns() into the container netns, which is not safe
in the multi-threaded BEAM.
""".

-export([init/1, attach_container/3, detach_container/2]).

%%%===================================================================
%%% Behaviour callbacks
%%%===================================================================

-doc """
Initialize IPVLAN link state.

Resolves the parent device's interface index and validates it is UP.
The parent device (e.g. eth0) must already exist and be configured
by the host operator -- erlkoenig does not manage it.

Config shape: #{network => #{mode => ipvlan, parent => <<\"eth0\">>,
                              ipvlan_mode => l3s, ...}, ...}
""".
-spec init(map()) -> {ok, map()} | {error, term()}.
init(#{network := #{parent := Parent} = NetCfg} = Cfg) ->
    IpvlanMode = maps:get(ipvlan_mode, NetCfg, l3s),
    ParentType = maps:get(parent_type, NetCfg, device),
    Subnet = maps:get(subnet, NetCfg, maps:get(subnet, Cfg, {10, 0, 0, 0})),
    Netmask = maps:get(netmask, NetCfg, maps:get(netmask, Cfg, 24)),
    case ParentType of
        dummy  -> ensure_dummy(Parent, Subnet, Netmask);
        device -> ok
    end,
    {ok, Sock} = erlkoenig_netlink:open(),
    try
        case get_ifindex(Sock, Parent) of
            {ok, ParentIdx} ->
                {ok, #{parent => Parent,
                       parent_type => ParentType,
                       parent_ifindex => ParentIdx,
                       ipvlan_mode => IpvlanMode}};
            {error, _} = Err ->
                logger:error("[zone_link_ipvlan] parent device ~s not found",
                             [Parent]),
                Err
        end
    after
        erlkoenig_netlink:close(Sock)
    end;
init(Config) ->
    {error, {missing_network_config, Config}}.

-doc """
Create an IPVLAN slave in the container's netns.

The slave is created with IFLA_NET_NS_PID so the kernel puts it
directly into the container's network namespace. No separate move
step needed (unlike veth).
""".
-spec attach_container(map(), binary(), non_neg_integer()) ->
    {ok, map()} | {error, term()}.
attach_container(#{parent_ifindex := ParentIdx, ipvlan_mode := IMode},
                 SlaveName, OsPid) ->
    {ok, Sock} = erlkoenig_netlink:open(),
    try
        Seq = erlkoenig_netlink:next_seq(),
        case erlkoenig_netlink:request(
               Sock, erlkoenig_netlink:msg_create_ipvlan(
                       Seq, SlaveName, ParentIdx, IMode, OsPid)) of
            ok ->
                {ok, #{slave => SlaveName, mode => ipvlan, os_pid => OsPid}};
            {error, _} = Err ->
                Err
        end
    after
        erlkoenig_netlink:close(Sock)
    end.

-doc """
Detach an IPVLAN slave -- intentional no-op.

The slave exists only inside the container's network namespace and is
not visible from the host netns. Cleanup paths:

  - Normal shutdown: container process exits → kernel destroys netns
    → slave is automatically removed.
  - Restart (erlkoenig_ct: stopping → creating): new clone() creates
    a fresh netns with a fresh slave. The old netns (and slave) is
    cleaned up by the kernel when the old process exits.

Explicit deletion from Erlang would require setns() into the container
netns, which is unsafe in the multi-threaded BEAM (scheduler thread
corruption). The C runtime could do it (it has setns capability), but
this spec explicitly excludes C changes.
""".
-spec detach_container(map(), map()) -> ok.
detach_container(_State, _AttachInfo) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

-spec get_ifindex(socket:socket(), binary()) -> {ok, integer()} | {error, term()}.
get_ifindex(Sock, Name) ->
    Seq = erlkoenig_netlink:next_seq(),
    Msg = erlkoenig_netlink:msg_get_link(Seq, Name),
    case socket:send(Sock, Msg) of
        ok    -> erlkoenig_netlink:recv_ifindex(Sock);
        Error -> Error
    end.

%% Create a dummy interface if it doesn't already exist.
%% Assigns the gateway IP (.1) and brings it UP.
-spec ensure_dummy(binary(), inet:ip4_address(), non_neg_integer()) -> ok.
ensure_dummy(Name, {A, B, C, _}, Netmask) ->
    NameStr = binary_to_list(Name),
    case filelib:is_dir("/sys/class/net/" ++ NameStr) of
        true ->
            logger:info("[zone_link_ipvlan] dummy ~s already exists", [Name]),
            ok;
        false ->
            logger:info("[zone_link_ipvlan] creating dummy ~s (~b.~b.~b.1/~b)",
                        [Name, A, B, C, Netmask]),
            GwIp = io_lib:format("~b.~b.~b.1/~b", [A, B, C, Netmask]),
            os_cmd_ok("ip link add " ++ NameStr ++ " type dummy"),
            os_cmd_ok("ip addr add " ++ lists:flatten(GwIp) ++ " dev " ++ NameStr),
            os_cmd_ok("ip link set " ++ NameStr ++ " up"),
            ok
    end.

-spec os_cmd_ok(string()) -> ok.
os_cmd_ok(Cmd) ->
    case os:cmd(Cmd ++ " 2>&1; echo $?") of
        Result ->
            Lines = string:split(string:trim(Result), "\n", all),
            case lists:last(Lines) of
                "0" -> ok;
                _   ->
                    logger:error("[zone_link_ipvlan] cmd failed: ~s -> ~s",
                                 [Cmd, Result]),
                    ok  %% best-effort
            end
    end.
