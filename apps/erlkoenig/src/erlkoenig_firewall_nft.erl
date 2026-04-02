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

-module(erlkoenig_firewall_nft).
-moduledoc """
nf_tables operations for per-container firewall chains.

Creates and manages a dedicated nf_tables table (erlkoenig_ct)
with:
  - Forward chain (filter, policy drop) for container isolation
  - Postrouting chain (nat, masquerade) for internet access
  - Prerouting chain (nat) for port-forwarding / DNAT
  - Per-container regular chains with isolation rules

All operations go through nfnl_server (erlkoenig_nft_srv) as atomic
batches.
""".

-export([setup_table/0, setup_table/1, teardown_table/0,
         add_container/3, add_container/4, add_container/5,
         remove_container/1,
         apply_zone_allows/2,
         compile_rule/1,
         compile_generic_rule/2,
         chain_name/1]).

%% NFPROTO_INET = 1
-define(FAMILY, 1).
-define(TABLE, <<"erlkoenig">>).
-define(FORWARD_CHAIN, <<"forward">>).
-define(POSTROUTING_CHAIN, <<"postrouting">>).
-define(PREROUTING_CHAIN, <<"prerouting">>).
-define(OUTPUT_CHAIN, <<"output">>).
-define(BRIDGE_NAME, <<"erlkoenig_br0">>).
-define(SERVER, erlkoenig_nft_srv).
-define(IP_FORWARD_PATH, "/proc/sys/net/ipv4/ip_forward").
-define(ROUTE_LOCALNET_FMT, "/proc/sys/net/ipv4/conf/~s/route_localnet").

%%====================================================================
%% Public API
%%====================================================================

-doc """
Create the erlkoenig_ct table with forward, postrouting, and
prerouting chains.

- forward: policy drop, per-container jump rules
- postrouting: masquerade for internet access
- prerouting: DNAT for port-forwarding

Also enables ip_forward so the kernel routes between interfaces.
""".
-spec setup_table() -> ok | {error, term()}.
setup_table() ->
    _ = ensure_ets(),
    %% Clean slate: delete table if it exists (ignore errors)
    _ = nfnl_server:apply_msgs(?SERVER, [
        fun(S) -> nft_delete:table(?FAMILY, ?TABLE, S) end
    ]),
    %% Enable IP forwarding + route_localnet on bridge
    _ = file:write_file(?IP_FORWARD_PATH, <<"1">>),
    enable_route_localnet(?BRIDGE_NAME),
    nfnl_server:apply_msgs(?SERVER, [
        fun(S) -> nft_table:add(?FAMILY, ?TABLE, S) end,

        %% Forward chain: per-container isolation
        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => ?TABLE,
            name     => ?FORWARD_CHAIN,
            hook     => forward,
            type     => filter,
            priority => 0,
            policy   => drop
        }, S) end,

        %% Established connections in forward chain (before per-container rules)
        nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
            nft_rules:ct_established_accept()),

        %% Postrouting chain: masquerade for internet access
        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => ?TABLE,
            name     => ?POSTROUTING_CHAIN,
            hook     => postrouting,
            type     => nat,
            priority => 100,
            policy   => accept
        }, S) end,

        %% Masquerade: only NAT traffic FROM the container subnet.
        nft_encode:rule_fun(inet, ?TABLE, ?POSTROUTING_CHAIN,
            subnet_masq_rule()),

        %% Masquerade localhost-originated DNAT traffic so containers
        %% can reply (src 127.x → bridge IP).
        nft_encode:rule_fun(inet, ?TABLE, ?POSTROUTING_CHAIN,
            loopback_masq_rule(?BRIDGE_NAME)),

        %% Prerouting chain: DNAT for port-forwarding (external traffic)
        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => ?TABLE,
            name     => ?PREROUTING_CHAIN,
            hook     => prerouting,
            type     => nat,
            priority => -100,
            policy   => accept
        }, S) end,

        %% Output chain: DNAT for locally-generated traffic (host -> container)
        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => ?TABLE,
            name     => ?OUTPUT_CHAIN,
            hook     => output,
            type     => nat,
            priority => -100,
            policy   => accept
        }, S) end
    ]).

-doc """
Create table with zone-aware masquerade rules.

Zones is a list of zone config maps:
  [#{bridge => <<"br0">>, subnet => {10,0,0,0}, netmask => 24,
     policy => allow_outbound}, ...]

Each zone with policy allow_outbound gets its own masquerade rule.
Zones with policy isolate or strict get no masquerade.
""".
-spec setup_table([map()]) -> ok | {error, term()}.
setup_table(Zones) when is_list(Zones) ->
    _ = ensure_ets(),
    _ = nfnl_server:apply_msgs(?SERVER, [
        fun(S) -> nft_delete:table(?FAMILY, ?TABLE, S) end
    ]),
    _ = file:write_file(?IP_FORWARD_PATH, <<"1">>),
    lists:foreach(fun(#{bridge := Br}) -> enable_route_localnet(Br) end, Zones),
    MasqRules = lists:append([zone_masq_rules(Z) || Z <- Zones]),
    LoopbackRules = [nft_encode:rule_fun(inet, ?TABLE, ?POSTROUTING_CHAIN,
                         loopback_masq_rule(Br))
                     || #{bridge := Br} <- Zones],
    nfnl_server:apply_msgs(?SERVER, [
        fun(S) -> nft_table:add(?FAMILY, ?TABLE, S) end,

        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => ?TABLE,
            name     => ?FORWARD_CHAIN,
            hook     => forward,
            type     => filter,
            priority => 0,
            policy   => drop
        }, S) end,

        nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
            nft_rules:ct_established_accept()),

        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => ?TABLE,
            name     => ?POSTROUTING_CHAIN,
            hook     => postrouting,
            type     => nat,
            priority => 100,
            policy   => accept
        }, S) end
    ] ++ MasqRules ++ LoopbackRules ++ [
        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => ?TABLE,
            name     => ?PREROUTING_CHAIN,
            hook     => prerouting,
            type     => nat,
            priority => -100,
            policy   => accept
        }, S) end,

        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => ?TABLE,
            name     => ?OUTPUT_CHAIN,
            hook     => output,
            type     => nat,
            priority => -100,
            policy   => accept
        }, S) end
    ]).

-doc "Generate masquerade rules for a zone.".
-spec zone_masq_rules(map()) -> [fun()].
zone_masq_rules(#{policy := allow_outbound, subnet := {A,B,C,_},
                  netmask := Mask, bridge := Bridge}) ->
    SubnetBin = <<A, B, C, 0>>,
    MaskBin = netmask_bin(Mask),
    BridgePadded = pad_ifname(Bridge),
    Rule = [nft_expr_ir:meta(nfproto, 1),
            nft_expr_ir:cmp(eq, 1, <<2>>),
            nft_expr_ir:ip_saddr(1),
            nft_expr_ir:bitwise(1, 1, MaskBin, <<0,0,0,0>>),
            nft_expr_ir:cmp(eq, 1, SubnetBin),
            nft_expr_ir:meta(oifname, 1),
            nft_expr_ir:cmp(neq, 1, BridgePadded),
            nft_expr_ir:masq()],
    [nft_encode:rule_fun(inet, ?TABLE, ?POSTROUTING_CHAIN, Rule)];
zone_masq_rules(_) ->
    [].

-doc "Delete the entire erlkoenig_ct table.".
-spec teardown_table() -> ok | {error, term()}.
teardown_table() ->
    nfnl_server:apply_msgs(?SERVER, [
        fun(S) -> nft_delete:table(?FAMILY, ?TABLE, S) end
    ]).

-doc "Add firewall rules for a container (no port-forwarding).".
-spec add_container(binary(), inet:ip_address(), binary()) -> ok | {error, term()}.
add_container(ContainerId, Ip, HostVeth) ->
    add_container(ContainerId, Ip, HostVeth, []).

-doc """
Add firewall rules for a container with port-forwarding.

Ports is a list of {HostPort, ContainerPort} tuples.
Creates a regular chain "ct_<id>" with default rules,
a jump rule in the forward chain, and DNAT rules in prerouting.
""".
-spec add_container(binary(), inet:ip_address(), binary(),
                    [{non_neg_integer(), non_neg_integer()}]) ->
    ok | {error, term()}.
add_container(ContainerId, Ip, HostVeth, Ports) ->
    add_container(ContainerId, Ip, HostVeth, Ports, #{}).

-doc """
Add firewall rules for a container with custom firewall term.

FirewallTerm is a map from the Erlkoenig DSL (or empty for defaults):
  #{chains => [#{rules => [...], ...}], sets => [...], counters => [...]}

When FirewallTerm is empty or has no chains, default rules are used
(ct_established + icmp + dns + accept).
""".
-spec add_container(binary(), inet:ip_address(), binary(),
                    [{non_neg_integer(), non_neg_integer()}],
                    map()) ->
    ok | {error, term()}.
add_container(ContainerId, Ip, HostVeth, Ports, FirewallTerm) ->
    _ = ensure_ets(),
    Chain = chain_name(ContainerId),
    IpBin = ip_to_binary(Ip),
    Rules = rules_from_term(FirewallTerm),
    RuleMsgs = [nft_encode:rule_fun(inet, ?TABLE, Chain, R) || R <- Rules],

    SetMsgs = sets_from_term(FirewallTerm),
    CounterMsgs = counters_from_term(FirewallTerm),

    %% For containers with port-forwarding, allow inbound traffic
    %% via oifname so DNAT'd packets pass the forward chain.
    FwdInboundMsgs = case Ports of
        [] -> [];
        _  -> [nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
                   nft_rules:oifname_accept(HostVeth))]
    end,

    Msgs = [
        %% 1. Create regular chain (no hook)
        fun(S) -> nft_chain:add_regular(?FAMILY,
            #{table => ?TABLE, name => Chain}, S) end
    ] ++ SetMsgs ++ CounterMsgs ++ RuleMsgs ++ [
        %% Jump rule in forward chain (container -> host)
        nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
            nft_rules:iifname_jump(HostVeth, Chain))
    ] ++ FwdInboundMsgs,

    %% DNAT rules in prerouting (external) + output (local) chains
    DnatMsgs = lists:append([
        [nft_encode:rule_fun(inet, ?TABLE, ?PREROUTING_CHAIN,
            nft_rules:tcp_dnat(HostPort, IpBin, ContainerPort)),
         nft_encode:rule_fun(inet, ?TABLE, ?OUTPUT_CHAIN,
            nft_rules:tcp_dnat(HostPort, IpBin, ContainerPort))]
     || {HostPort, ContainerPort} <- Ports
    ]),

    %% Store container info for rebuild on remove
    ets:insert(erlkoenig_firewall_ports, {ContainerId, HostVeth, Ip, Ports}),
    nfnl_server:apply_msgs(?SERVER, Msgs ++ DnatMsgs).

-doc """
Remove all firewall rules for a container.

Flushes all shared chains (forward, prerouting, output), deletes
the container chain, then rebuilds shared-chain rules for all
remaining containers.
""".
-spec remove_container(binary()) -> ok | {error, term()}.
remove_container(ContainerId) ->
    _ = ensure_ets(),
    Chain = chain_name(ContainerId),
    %% Remove this container from ETS
    ets:delete(erlkoenig_firewall_ports, ContainerId),
    %% Remaining containers
    Remaining = ets:tab2list(erlkoenig_firewall_ports),
    %% 1. Flush shared chains + container chain, then delete container chain
    FlushMsgs = [
        fun(S) -> nft_delete:flush_chain(?FAMILY, ?TABLE, ?FORWARD_CHAIN, S) end,
        fun(S) -> nft_delete:flush_chain(?FAMILY, ?TABLE, ?PREROUTING_CHAIN, S) end,
        fun(S) -> nft_delete:flush_chain(?FAMILY, ?TABLE, ?OUTPUT_CHAIN, S) end,
        fun(S) -> nft_delete:flush_chain(?FAMILY, ?TABLE, Chain, S) end,
        fun(S) -> nft_delete:chain(?FAMILY, ?TABLE, Chain, S) end
    ],
    %% 2. Re-add base rules for shared chains
    BaseMsgs = [
        nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
            nft_rules:ct_established_accept())
    ],
    %% 3. Re-add jump + DNAT rules for remaining containers
    RebuildMsgs = lists:append([rebuild_shared_rules(R) || R <- Remaining]),
    nfnl_server:apply_msgs(?SERVER, FlushMsgs ++ BaseMsgs ++ RebuildMsgs).

-doc "Rebuild forward jump + DNAT rules for one container.".
-spec rebuild_shared_rules(tuple()) -> [fun()].
rebuild_shared_rules({_Id, Veth, _Ip, []}) ->
    Chain2 = chain_name(_Id),
    [nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
        nft_rules:iifname_jump(Veth, Chain2))];
rebuild_shared_rules({_Id, Veth, Ip, Ports}) ->
    Chain2 = chain_name(_Id),
    IpBin = ip_to_binary(Ip),
    [nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
        nft_rules:iifname_jump(Veth, Chain2)),
     nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
        nft_rules:oifname_accept(Veth))] ++
    lists:append([
        [nft_encode:rule_fun(inet, ?TABLE, ?PREROUTING_CHAIN,
            nft_rules:tcp_dnat(HP, IpBin, CP)),
         nft_encode:rule_fun(inet, ?TABLE, ?OUTPUT_CHAIN,
            nft_rules:tcp_dnat(HP, IpBin, CP))]
     || {HP, CP} <- Ports
    ]).

%%====================================================================
%% Internal
%%====================================================================

-doc """
Masquerade only traffic from the container subnet.
Reads subnet/netmask from app config. The subnet match ensures
only container traffic gets NAT'd -- loopback, host traffic, and
inter-zone traffic are never affected (see docs/ZONES.md).
""".
-spec subnet_masq_rule() -> list().
subnet_masq_rule() ->
    {A, B, C, _} = application:get_env(erlkoenig, subnet, {10, 0, 0, 0}),
    Netmask = application:get_env(erlkoenig, netmask, 24),
    SubnetBin = <<A, B, C, 0>>,
    MaskBin = netmask_bin(Netmask),
    BridgePadded = pad_ifname(?BRIDGE_NAME),
    %% nfproto == ipv4 AND ip saddr & mask == subnet AND oifname != bridge → masquerade
    [nft_expr_ir:meta(nfproto, 1),
     nft_expr_ir:cmp(eq, 1, <<2>>),   %% NFPROTO_IPV4 = 2
     nft_expr_ir:ip_saddr(1),
     nft_expr_ir:bitwise(1, 1, MaskBin, <<0,0,0,0>>),
     nft_expr_ir:cmp(eq, 1, SubnetBin),
     nft_expr_ir:meta(oifname, 1),
     nft_expr_ir:cmp(neq, 1, BridgePadded),
     nft_expr_ir:masq()].

-spec pad_ifname(binary()) -> binary().
pad_ifname(Name) when byte_size(Name) =< 16 ->
    Pad = 16 - byte_size(Name),
    <<Name/binary, 0:(Pad * 8)>>.

-spec netmask_bin(0..32) -> binary().
netmask_bin(Bits) ->
    Mask = (16#FFFFFFFF bsl (32 - Bits)) band 16#FFFFFFFF,
    <<Mask:32/big>>.

-doc """
Masquerade traffic from 127.0.0.0/8 going to a bridge interface.
This allows localhost DNAT (host -> container via 127.0.0.1:port) to work.
""".
-spec loopback_masq_rule(binary()) -> list().
loopback_masq_rule(BridgeName) ->
    BridgePadded = pad_ifname(BridgeName),
    [nft_expr_ir:meta(nfproto, 1),
     nft_expr_ir:cmp(eq, 1, <<2>>),
     nft_expr_ir:ip_saddr(1),
     nft_expr_ir:bitwise(1, 1, <<255, 0, 0, 0>>, <<0, 0, 0, 0>>),
     nft_expr_ir:cmp(eq, 1, <<127, 0, 0, 0>>),
     nft_expr_ir:meta(oifname, 1),
     nft_expr_ir:cmp(eq, 1, BridgePadded),
     nft_expr_ir:masq()].

-doc "Enable route_localnet for an interface so localhost DNAT works.".
-spec enable_route_localnet(binary()) -> ok.
enable_route_localnet(IfName) ->
    Path = lists:flatten(io_lib:format(?ROUTE_LOCALNET_FMT,
                                       [binary_to_list(IfName)])),
    _ = file:write_file(Path, <<"1">>),
    ok.

-spec chain_name(binary()) -> binary().
chain_name(ContainerId) ->
    Short = binary:part(ContainerId, 0, min(12, byte_size(ContainerId))),
    <<"ct_", Short/binary>>.

-spec ip_to_binary(inet:ip_address()) -> binary().
ip_to_binary({A, B, C, D}) ->
    <<A, B, C, D>>;
ip_to_binary({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

%% --- Term-based rule compilation ---

-doc "Extract nft_rules from a DSL firewall term. Returns a list of compiled rule expression lists.".
-spec rules_from_term(map()) -> [list()].
rules_from_term(#{chains := [#{rules := Rules} | _]}) ->
    [compile_rule(R) || R <- Rules];
rules_from_term(_) ->
    %% Default rules (backward compatible)
    [nft_rules:ct_established_accept(),
     nft_rules:icmp_accept(),
     nft_rules:udp_accept(53),
     [nft_expr_ir:accept()]].

-doc "Create nft set messages from a DSL firewall term.".
-spec sets_from_term(map()) -> [fun()].
sets_from_term(#{sets := Sets}) when is_list(Sets), Sets =/= [] ->
    [set_msg(S) || S <- Sets];
sets_from_term(_) ->
    [].

-doc "Create nft counter messages from a DSL firewall term.".
-spec counters_from_term(map()) -> [fun()].
counters_from_term(#{counters := Counters}) when is_list(Counters), Counters =/= [] ->
    [fun(S) ->
        nft_object:add_counter(?FAMILY, ?TABLE, iolist_to_binary(C), S)
     end || C <- Counters];
counters_from_term(_) ->
    [].

-doc "Convert a single DSL rule atom/tuple to nft_rules expression list.".
-spec compile_rule(atom() | tuple()) -> list().

%% Generic rule: {rule, Verdict, #{opt => val, ...}}
compile_rule({rule, Verdict, Opts}) when is_map(Opts) ->
    compile_generic_rule(Verdict, Opts);

compile_rule(ct_established_accept) ->
    nft_rules:ct_established_accept();
compile_rule(icmp_accept) ->
    nft_rules:icmp_accept();
compile_rule(accept) ->
    [nft_expr_ir:accept()];
compile_rule({tcp_accept, Port}) ->
    nft_rules:tcp_accept(Port);
compile_rule({tcp_accept, Port, Counter}) ->
    nft_rules:tcp_accept_named(Port, iolist_to_binary(Counter));
compile_rule({tcp_accept_limited, Port, Counter, #{rate := Rate, burst := Burst}}) ->
    nft_rules:tcp_accept_limited(Port, iolist_to_binary(Counter),
                                 #{rate => Rate, burst => Burst});
compile_rule({tcp_port_range_accept, From, To}) ->
    nft_rules:tcp_port_range_accept(From, To);
compile_rule({tcp_reject, Port}) ->
    nft_rules:tcp_reject(Port);
compile_rule({udp_accept, Port}) ->
    nft_rules:udp_accept(Port);
compile_rule({udp_accept, Port, Counter}) ->
    nft_rules:udp_accept_named(Port, iolist_to_binary(Counter));
compile_rule({udp_port_range_accept, From, To}) ->
    nft_rules:udp_port_range_accept(From, To);
compile_rule({protocol_accept, Proto}) ->
    nft_rules:protocol_accept(Proto);
compile_rule({ip_saddr_accept, Ip}) ->
    nft_rules:ip_saddr_accept(Ip);
compile_rule({ip_saddr_drop, Ip}) ->
    nft_rules:ip_saddr_drop(Ip);
compile_rule({iifname_accept, Name}) ->
    nft_rules:iifname_accept(iolist_to_binary(Name));
compile_rule({set_lookup_drop, SetName}) ->
    nft_rules:set_lookup_drop(iolist_to_binary(SetName));
compile_rule({set_lookup_drop, SetName, Counter}) ->
    nft_rules:set_lookup_drop_named(iolist_to_binary(SetName), iolist_to_binary(Counter));
compile_rule({connlimit_drop, Max, Offset}) ->
    nft_rules:connlimit_drop(Max, Offset);
compile_rule({log_drop, Prefix}) ->
    nft_rules:log_drop(iolist_to_binary(Prefix));
compile_rule({log_drop, Prefix, Counter}) ->
    nft_rules:log_drop_named(iolist_to_binary(Prefix), iolist_to_binary(Counter));
compile_rule({log_reject, Prefix}) ->
    nft_rules:log_reject(iolist_to_binary(Prefix));
compile_rule({dnat, Ip, Port}) ->
    nft_rules:tcp_dnat(Port, ip_to_binary(Ip), Port);
compile_rule(Unknown) ->
    logger:warning("erlkoenig_firewall_nft: unknown rule ~p, skipping", [Unknown]),
    [].

-doc "Create a set add message.".
-spec set_msg(tuple()) -> fun().
set_msg({Name, Type}) ->
    fun(S) -> nft_set:add(?FAMILY, #{
        table => ?TABLE,
        name  => iolist_to_binary(Name),
        type  => set_type_atom(Type)}, S) end;
set_msg({Name, Type, #{timeout := Timeout} = Opts}) ->
    Flags = maps:get(flags, Opts, []),
    fun(S) -> nft_set:add(?FAMILY, #{
        table   => ?TABLE,
        name    => iolist_to_binary(Name),
        type    => set_type_atom(Type),
        flags   => Flags,
        timeout => Timeout}, S) end.

-spec set_type_atom(atom()) -> atom().
set_type_atom(ipv4_addr) -> ipv4_addr;
set_type_atom(ipv6_addr) -> ipv6_addr.

-doc "Ensure the ETS table for tracking container port mappings exists.".
ensure_ets() ->
    case ets:whereis(erlkoenig_firewall_ports) of
        undefined ->
            ets:new(erlkoenig_firewall_ports,
                    [set, named_table, public, {read_concurrency, true}]);
        _Tid ->
            ok
    end.

%%====================================================================
%% Zone allow directives → nftables rules
%%====================================================================

-doc """
Apply zone-level network policy to the erlkoenig_ct forward chain.

Translates allow directives into nftables rules:
  dns              → allow UDP/TCP port 53 to gateway IP
  gateway          → allow all traffic to gateway IP
  {gateway, Ports} → allow specific TCP ports to gateway IP
  {internet, Via}  → masquerade via interface + allow forwarding
  {zone, Name}     → allow inter-zone forwarding (not yet implemented)

Rules are added to the forward chain after ct_established_accept.
""".
-spec apply_zone_allows(map(), binary()) -> ok | {error, term()}.
apply_zone_allows(#{allows := Allows, gateway := Gateway}, BridgeBin)
  when is_list(Allows) ->
    GwIp = ip_to_binary(Gateway),
    Rules = lists:flatmap(fun(Allow) ->
        allow_to_rules(Allow, GwIp, BridgeBin)
    end, Allows),
    case Rules of
        [] ->
            logger:info("[firewall] zone ~s: no allows, fully isolated", [BridgeBin]),
            ok;
        _ ->
            RuleFuns = [nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN, R) || R <- Rules],
            case nfnl_server:apply_msgs(?SERVER, RuleFuns) of
                ok ->
                    logger:info("[firewall] zone ~s: ~p allow rules applied",
                               [BridgeBin, length(Rules)]),
                    ok;
                {error, Reason} ->
                    logger:warning("[firewall] zone ~s: allow rules failed: ~p",
                                  [BridgeBin, Reason]),
                    {error, Reason}
            end
    end;
apply_zone_allows(_, _) ->
    ok.

%% Translate a single allow directive into nftables rule expressions.
-spec allow_to_rules(atom() | tuple(), binary(), binary()) -> [list()].
allow_to_rules(dns, GwIp, _Bridge) ->
    %% Allow UDP+TCP port 53 to gateway (DNS)
    [
        %% UDP DNS
        [nft_expr_ir:meta(nfproto, 1),
         nft_expr_ir:cmp(eq, 1, <<2>>),
         nft_expr_ir:ip_daddr(1),
         nft_expr_ir:cmp(eq, 1, GwIp),
         nft_expr_ir:meta(l4proto, 1),
         nft_expr_ir:cmp(eq, 1, <<17>>),
         nft_expr_ir:payload(transport, 2, 2, 1),
         nft_expr_ir:cmp(eq, 1, <<53:16/big>>),
         nft_expr_ir:accept()],
        %% TCP DNS
        [nft_expr_ir:meta(nfproto, 1),
         nft_expr_ir:cmp(eq, 1, <<2>>),
         nft_expr_ir:ip_daddr(1),
         nft_expr_ir:cmp(eq, 1, GwIp),
         nft_expr_ir:meta(l4proto, 1),
         nft_expr_ir:cmp(eq, 1, <<6>>),
         nft_expr_ir:payload(transport, 2, 2, 1),
         nft_expr_ir:cmp(eq, 1, <<53:16/big>>),
         nft_expr_ir:accept()]
    ];
allow_to_rules(gateway, GwIp, _Bridge) ->
    %% Allow all traffic to gateway IP
    [[nft_expr_ir:meta(nfproto, 1),
      nft_expr_ir:cmp(eq, 1, <<2>>),
      nft_expr_ir:ip_daddr(1),
      nft_expr_ir:cmp(eq, 1, GwIp),
      nft_expr_ir:accept()]];
allow_to_rules({gateway, Ports}, GwIp, _Bridge) when is_list(Ports) ->
    %% Allow specific TCP ports to gateway IP
    lists:map(fun(Port) ->
        [nft_expr_ir:meta(nfproto, 1),
         nft_expr_ir:cmp(eq, 1, <<2>>),
         nft_expr_ir:ip_daddr(1),
         nft_expr_ir:cmp(eq, 1, GwIp),
         nft_expr_ir:meta(l4proto, 1),
         nft_expr_ir:cmp(eq, 1, <<6>>),
         nft_expr_ir:payload(transport, 2, 2, 1),
         nft_expr_ir:cmp(eq, 1, <<Port:16/big>>),
         nft_expr_ir:accept()]
    end, Ports);
allow_to_rules({internet, Via}, _GwIp, _Bridge) ->
    %% Allow forwarding to external interface (masquerade handled separately)
    ViaB = iolist_to_binary(Via),
    [[nft_expr_ir:meta(oifname, 1),
      nft_expr_ir:cmp(eq, 1, pad_ifname(ViaB)),
      nft_expr_ir:accept()]];
allow_to_rules({zone, _TargetZone}, _GwIp, _Bridge) ->
    %% Inter-zone forwarding — TODO
    logger:warning("[firewall] allow :zone not yet implemented"),
    [];
allow_to_rules(Unknown, _GwIp, _Bridge) ->
    logger:warning("[firewall] unknown allow directive: ~p", [Unknown]),
    [].

%% Interface name matching — handles wildcards ("vh_*") and exact names.
%% Wildcard: compare only the prefix bytes (before *), not padded to 16.
%% Exact: pad to 16 bytes and compare all.
-spec ifname_match(iifname | oifname, eq | neq, binary()) -> list().
ifname_match(MetaKey, Op, Name) ->
    case binary:split(Name, <<"*">>) of
        [Prefix, <<>>] ->
            %% Wildcard: "vh_*" → compare prefix only
            %% nft uses cmp with just the prefix bytes (no padding)
            [nft_expr_ir:meta(MetaKey, 1),
             nft_expr_ir:cmp(Op, 1, <<Prefix/binary, 0>>)];
        _ ->
            %% Exact match: pad to IFNAMSIZ
            [nft_expr_ir:meta(MetaKey, 1),
             nft_expr_ir:cmp(Op, 1, pad_ifname(Name))]
    end.

%% pad_ifname/1 defined above (shared with zone masq rules).

%%====================================================================
%% Generic rule compiler
%%====================================================================

-doc """
Compile a generic rule {rule, Verdict, Opts} into nft_expr_ir expressions.

Opts is a map with match conditions and modifiers. The compiler builds
expressions in order: matches first, then modifiers, then verdict.
""".
-spec compile_generic_rule(atom(), map()) -> list().
compile_generic_rule(Verdict, Opts) ->
    Exprs = [],

    %% Conntrack state
    Exprs1 = case maps:find(ct, Opts) of
        {ok, established} ->
            Exprs ++ nft_rules:ct_established_accept();
        _ -> Exprs
    end,

    %% ICMP
    Exprs2 = case maps:find(icmp, Opts) of
        {ok, true} ->
            Exprs1 ++ nft_rules:icmp_accept();
        _ -> Exprs1
    end,

    %% If ct or icmp matched, they already include the verdict — return early
    case {maps:is_key(ct, Opts), maps:is_key(icmp, Opts)} of
        {true, _} -> Exprs1;
        {_, true} -> Exprs2;
        _ ->
            %% Build match expressions
            Matches = compile_generic_matches(Opts),

            %% Modifiers (counter, limit, log)
            Mods = compile_generic_modifiers(Opts),

            %% Verdict
            V = compile_generic_verdict(Verdict, Opts),

            Matches ++ Mods ++ V
    end.

-spec compile_generic_matches(map()) -> list().
compile_generic_matches(Opts) ->
    lists:flatten(lists:filtermap(fun(Match) -> Match end, [
        compile_match_iif(Opts),
        compile_match_oif(Opts),
        compile_match_oif_neq(Opts),
        compile_match_saddr(Opts),
        compile_match_daddr(Opts),
        compile_match_tcp(Opts),
        compile_match_udp(Opts),
        compile_match_set(Opts)
    ])).

compile_match_iif(#{iif := Name}) ->
    {true, ifname_match(iifname, eq, iolist_to_binary(Name))};
compile_match_iif(_) -> false.

compile_match_oif(#{oif := Name}) ->
    {true, ifname_match(oifname, eq, iolist_to_binary(Name))};
compile_match_oif(_) -> false.

compile_match_oif_neq(#{oif_neq := Name}) ->
    {true, ifname_match(oifname, neq, iolist_to_binary(Name))};
compile_match_oif_neq(_) -> false.

compile_match_saddr(#{saddr := {A, B, C, D, Prefix}}) ->
    Ip = <<A, B, C, D>>,
    case Prefix of
        32 ->
            {true, [nft_expr_ir:meta(nfproto, 1),
                    nft_expr_ir:cmp(eq, 1, <<2>>),
                    nft_expr_ir:ip_saddr(1),
                    nft_expr_ir:cmp(eq, 1, Ip)]};
        _ ->
            Mask = subnet_mask(Prefix),
            MaskedNet = apply_mask(Ip, Mask),
            {true, [nft_expr_ir:meta(nfproto, 1),
                    nft_expr_ir:cmp(eq, 1, <<2>>),
                    nft_expr_ir:ip_saddr(1),
                    nft_expr_ir:bitwise(1, 1, Mask, <<0, 0, 0, 0>>),
                    nft_expr_ir:cmp(eq, 1, MaskedNet)]}
    end;
compile_match_saddr(_) -> false.

compile_match_daddr(#{daddr := {A, B, C, D, Prefix}}) ->
    Ip = <<A, B, C, D>>,
    case Prefix of
        32 ->
            {true, [nft_expr_ir:meta(nfproto, 1),
                    nft_expr_ir:cmp(eq, 1, <<2>>),
                    nft_expr_ir:ip_daddr(1),
                    nft_expr_ir:cmp(eq, 1, Ip)]};
        _ ->
            Mask = subnet_mask(Prefix),
            MaskedNet = apply_mask(Ip, Mask),
            {true, [nft_expr_ir:meta(nfproto, 1),
                    nft_expr_ir:cmp(eq, 1, <<2>>),
                    nft_expr_ir:ip_daddr(1),
                    nft_expr_ir:bitwise(1, 1, Mask, <<0, 0, 0, 0>>),
                    nft_expr_ir:cmp(eq, 1, MaskedNet)]}
    end;
compile_match_daddr(_) -> false.

compile_match_tcp(#{tcp := Port}) when is_integer(Port) ->
    {true, [nft_expr_ir:meta(l4proto, 1),
            nft_expr_ir:cmp(eq, 1, <<6>>),
            nft_expr_ir:payload(transport, 2, 2, 1),
            nft_expr_ir:cmp(eq, 1, <<Port:16/big>>)]};
compile_match_tcp(_) -> false.

compile_match_udp(#{udp := Port}) when is_integer(Port) ->
    {true, [nft_expr_ir:meta(l4proto, 1),
            nft_expr_ir:cmp(eq, 1, <<17>>),
            nft_expr_ir:payload(transport, 2, 2, 1),
            nft_expr_ir:cmp(eq, 1, <<Port:16/big>>)]};
compile_match_udp(_) -> false.

compile_match_set(#{set := SetName}) ->
    SetBin = iolist_to_binary(SetName),
    {true, [nft_expr_ir:meta(nfproto, 1),
            nft_expr_ir:cmp(eq, 1, <<2>>),
            nft_expr_ir:ip_saddr(1),
            nft_expr_ir:lookup(1, SetBin)]};
compile_match_set(_) -> false.

-spec compile_generic_modifiers(map()) -> list().
compile_generic_modifiers(Opts) ->
    Mods = [],
    Mods1 = case maps:find(counter, Opts) of
        {ok, Name} -> Mods ++ [nft_expr_ir:objref_counter(iolist_to_binary(Name))];
        _ -> Mods
    end,
    Mods2 = case maps:find(limit, Opts) of
        {ok, #{rate := Rate, burst := Burst}} ->
            Mods1 ++ [nft_expr_ir:limit(Rate, Burst)];
        _ -> Mods1
    end,
    Mods3 = case maps:find(log, Opts) of
        {ok, Prefix} -> Mods2 ++ [nft_expr_ir:log(#{prefix => iolist_to_binary(Prefix)})];
        _ -> Mods2
    end,
    Mods3.

-spec compile_generic_verdict(atom(), map()) -> list().
compile_generic_verdict(accept, _Opts) -> [nft_expr_ir:accept()];
compile_generic_verdict(drop, _Opts) -> [nft_expr_ir:drop()];
compile_generic_verdict(reject, _Opts) -> [nft_expr_ir:reject()];
compile_generic_verdict(masquerade, _Opts) -> [nft_expr_ir:masq()];
compile_generic_verdict(return, _Opts) -> [nft_expr_ir:return()];
compile_generic_verdict(jump, #{chain := Chain}) ->
    [nft_expr_ir:jump(iolist_to_binary(Chain))];
compile_generic_verdict(_, _) -> [nft_expr_ir:accept()].

%% Helper: build a /prefix subnet mask as 4-byte binary
-spec subnet_mask(0..32) -> binary().
subnet_mask(Prefix) ->
    M = (16#FFFFFFFF bsl (32 - Prefix)) band 16#FFFFFFFF,
    <<M:32/big>>.

%% Helper: apply mask to IP
-spec apply_mask(binary(), binary()) -> binary().
apply_mask(<<A:32/big>>, <<M:32/big>>) ->
    <<(A band M):32/big>>.
