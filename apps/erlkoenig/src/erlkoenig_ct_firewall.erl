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

-module(erlkoenig_ct_firewall).
-moduledoc """
nf_tables operations for per-container firewall chains.

Owns two logical chain groups in fixed per-owner tables:

  * **Filter side** — forward chain (policy drop) plus the
    per-container helper chains and their sets/counters. Lives in
    `erlkoenig_zone`.
  * **NAT side** — prerouting/dstnat (port-forwards), postrouting/
    srcnat (masquerade for container egress) and the
    output/dstnat chain (host-locally-generated traffic). Lives
    in `erlkoenig_ct`.

The helpers `forward_table/0` and `nat_table/0` make the
distinction explicit at every call site. All operations go
through `nfnl_server` (`erlkoenig_nft_srv`) as atomic batches.
""".

-export([setup_table/0, setup_table/1, teardown_table/0,
         add_container/3, add_container/4, add_container/5, add_container/6,
         remove_container/1,
         apply_zone_allows/2,
         compile_rule/1,
         compile_generic_rule/2,
         chain_name/1,
         inject_drop_counter/2,
         inject_drop_observability/3,
         next_nflog_group/0,
         nflog_group_for_zone/1,
         set_msg/1,
         %% Phase 6e.1.a: forward_table/0 is the production
         %% choke point for the zone-owned forward-chain table.
         %% `erlkoenig_config_nft:apply_zone_chains/2` and
         %% `apply_pod_chains_for_replicas/5` route through it,
         %% so the export must be unconditional — it was TEST-
         %% only in 6c when nothing outside this module called
         %% it, and that gate would crash the writer with
         %% `undef` in non-TEST builds.
         forward_table/0]).

-ifdef(TEST).
-export([build_setup_msgs/3, build_remove_msgs/3,
         build_remove_target_msgs/2, build_remove_counter_msgs/1,
         build_rebuild_shared_msgs/1, nat_table/0,
         enable_ip_forward/1]).
-endif.

-include("nft_tables.hrl").

%% NFPROTO_INET = 1
-define(FAMILY, 1).
-define(TABLE, ?EK_NFT_TABLE_ZONE).
-define(FORWARD_CHAIN, <<"forward">>).
-define(POSTROUTING_CHAIN, <<"postrouting">>).
-define(PREROUTING_CHAIN, <<"prerouting">>).
-define(OUTPUT_CHAIN, <<"output">>).
-define(SERVER, erlkoenig_nft_srv).
-define(IP_FORWARD_PATH, "/proc/sys/net/ipv4/ip_forward").

%% --- Owner table helpers ---

-spec nat_table() -> binary().
nat_table() ->
    ?EK_NFT_TABLE_CT.

-spec forward_table() -> binary().
forward_table() ->
    ?EK_NFT_TABLE_ZONE.

%% Build the setup batch as one atomic list of msg-funs. Pure
%% function; isolates the table layout decision from the
%% gen_server send so tests can inspect the batch without a live
%% nfnl_server.
%%
%% Layout invariants:
%% - Forward table is always added (idempotent).
%% - NAT table is added only when it differs from the forward
%%   table.
%% - Forward chain + established-accept land in forward table.
%% - postrouting/prerouting/output (NAT) land in NAT table.
%% - Extra (masq/loopback rules from ADR-pre work) are appended at
%%   the end so the kernel sees them in one transaction.
-spec build_setup_msgs(binary(), binary(), [fun()]) -> [fun()].
build_setup_msgs(FwdTable, NatTable, Extra) when is_list(Extra) ->
    TableMsgs =
        case NatTable of
            FwdTable ->
                [fun(S) -> nft_table:add(?FAMILY, FwdTable, S) end];
            _ ->
                [fun(S) -> nft_table:add(?FAMILY, FwdTable, S) end,
                 fun(S) -> nft_table:add(?FAMILY, NatTable, S) end]
        end,
    FwdMsgs = [
        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => FwdTable,
            name     => ?FORWARD_CHAIN,
            hook     => forward,
            type     => filter,
            priority => 0,
            policy   => drop
        }, S) end,
        nft_encode:rule_fun(inet, FwdTable, ?FORWARD_CHAIN,
            nft_rules:ct_established_accept())
    ],
    NatMsgs = [
        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => NatTable,
            name     => ?POSTROUTING_CHAIN,
            hook     => postrouting,
            type     => nat,
            priority => 100,
            policy   => accept
        }, S) end,
        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => NatTable,
            name     => ?PREROUTING_CHAIN,
            hook     => prerouting,
            type     => nat,
            priority => -100,
            policy   => accept
        }, S) end,
        fun(S) -> nft_chain:add(?FAMILY, #{
            table    => NatTable,
            name     => ?OUTPUT_CHAIN,
            hook     => output,
            type     => nat,
            priority => -100,
            policy   => accept
        }, S) end
    ],
    TableMsgs ++ FwdMsgs ++ NatMsgs ++ Extra.

%%====================================================================
%% Public API
%%====================================================================

-doc """
Create the table(s) this module owns and install their base
chains. Sent to the kernel as one atomic netlink batch so a
partial failure cannot leave half a layout installed.

`erlkoenig_ct` is added alongside the forward table and the NAT
chains live there:

  * forward (filter, policy drop, in `forward_table()`) — per-container jump rules
  * postrouting (nat, srcnat, in `nat_table()`) — masquerade for container egress
  * prerouting (nat, dstnat, in `nat_table()`) — DNAT for port-forwarding
  * output (nat, dstnat, in `nat_table()`) — host-locally-generated DNAT
    (note: §10.6 §4.1 deviation — decision deferred)

Also enables ip_forward so the kernel routes between interfaces.
""".
-spec setup_table() -> ok | {error, term()}.
setup_table() ->
    _ = ensure_ets(),
    case enable_ip_forward() of
        ok ->
            %% Selective cleanup: flush own chains instead of deleting the entire table.
            %% Other subsystems (erlkoenig_config/DSL) may have chains/maps in this table.
            flush_own_chains(),
            apply_setup_msgs(build_setup_msgs(forward_table(), nat_table(), []));
        {error, _} = IpForwardErr ->
            IpForwardErr
    end.

-doc """
Same atomic setup as `setup_table/0` but accepts a zone list for
API shape compatibility. Tables and chains are identical to
`setup_table/0`.

Zones is a list of zone config maps (IPVLAN-only zones do not
need masquerade/route_localnet — see ADR-0020):
  [#{subnet => {10,0,0,0}, netmask => 24, policy => allow_outbound}, ...]

Policies `isolate` and `strict` add no additional rules;
`allow_outbound` still reserves the hook for future per-zone
egress rules.
""".
-spec setup_table([map()]) -> ok | {error, term()}.
setup_table(Zones) when is_list(Zones) ->
    _ = ensure_ets(),
    case enable_ip_forward() of
        ok ->
            %% Selective cleanup: flush own chains instead of deleting the entire table.
            flush_own_chains(),
            %% ADR-0020: IPVLAN-only, no link-layer masquerade/route_localnet needed.
            MasqRules = [],
            LoopbackRules = [],
            Extra = MasqRules ++ LoopbackRules,
            apply_setup_msgs(build_setup_msgs(forward_table(), nat_table(), Extra));
        {error, _} = IpForwardErr ->
            IpForwardErr
    end.

enable_ip_forward() ->
    enable_ip_forward(?IP_FORWARD_PATH).

enable_ip_forward(Path) ->
    case file:write_file(Path, <<"1">>) of
        ok ->
            ok;
        {error, Reason} ->
            logger:error("erlkoenig_ct_firewall: cannot enable ip_forward "
                         "(~s): ~p", [Path, Reason]),
            {error, {ip_forward_enable_failed, Path, Reason}}
    end.

apply_setup_msgs(Msgs) ->
    try nfnl_server:apply_msgs(?SERVER, Msgs) of
        ok ->
            ok;
        {error, Reason} ->
            {error, {setup_batch_failed, Reason}}
    catch
        exit:{noproc, _} = Err ->
            {error, {setup_batch_failed, Err}};
        Class:Reason ->
            {error, {setup_batch_failed, {Class, Reason}}}
    end.


-doc """
Delete the tables this module owns: the zone forward table and
the dedicated NAT table `erlkoenig_ct`.
""".
-spec teardown_table() -> ok | {error, term()}.
teardown_table() ->
    FwdTable = forward_table(),
    NatTable = nat_table(),
    Tables = case NatTable of
        FwdTable -> [FwdTable];
        _        -> [FwdTable, NatTable]
    end,
    %% Best-effort delete of every owned table — a missing table on
    %% one side must not block the other. Aggregate the result so a
    %% later success does not mask an earlier failure.
    lists:foldl(
        fun(Table, Acc) ->
            Result = nfnl_server:apply_msgs(?SERVER, [
                fun(S) -> nft_delete:table(?FAMILY, Table, S) end
            ]),
            case {Acc, Result} of
                {ok, ok}            -> ok;
                {ok, {error, _}}    -> Result;
                {{error, _}, _}     -> Acc
            end
        end,
        ok,
        Tables
    ).

%% Flush own chains without deleting the table.
%% Preserves chains/maps/sets from other subsystems (erlkoenig_config/DSL).
flush_own_chains() ->
    FwdTable = forward_table(),
    NatTable = nat_table(),
    %% Filter chains live in the forward table; NAT chains live in
    %% the NAT table.
    FilterChains = [?FORWARD_CHAIN],
    NatChains    = [?POSTROUTING_CHAIN, ?PREROUTING_CHAIN, ?OUTPUT_CHAIN],
    %% Also flush per-container chains from ETS — they are filter
    %% helpers that live with the forward chain.
    PerCtChains = case ets:info(erlkoenig_firewall_ports) of
        undefined -> [];
        _ ->
            [element(5, R) || R <- ets:tab2list(erlkoenig_firewall_ports),
                              is_tuple(R), tuple_size(R) =:= 5]
    end,
    Targets = [{FwdTable, CN} || CN <- FilterChains ++ PerCtChains]
        ++ [{NatTable, CN} || CN <- NatChains],
    lists:foreach(fun({Table, CN}) ->
        _ = nfnl_server:apply_msgs(?SERVER, [
            fun(S) -> nft_delete:flush_chain(?FAMILY, Table, CN, S) end
        ]),
        _ = nfnl_server:apply_msgs(?SERVER, [
            fun(S) -> nft_delete:chain(?FAMILY, Table, CN, S) end
        ])
    end, Targets),
    ok.

-doc "Add firewall rules for a container (no port-forwarding).".
-spec add_container(binary(), inet:ip_address(), undefined | binary()) ->
    ok | {error, term()}.
add_container(ContainerId, Ip, HostIface) ->
    add_container(ContainerId, Ip, HostIface, []).

-doc """
Add firewall rules for a container with port-forwarding.

Ports is a list of {HostPort, ContainerPort} tuples.
Creates a regular chain "ct_<id>" with default rules,
a jump rule in the forward chain, and DNAT rules in prerouting.
""".
-spec add_container(binary(), inet:ip_address(), undefined | binary(),
                    [{non_neg_integer(), non_neg_integer()}]) ->
    ok | {error, term()}.
add_container(ContainerId, Ip, HostIface, Ports) ->
    add_container(ContainerId, Ip, HostIface, Ports, #{}).

-doc """
Add firewall rules for a container with custom firewall term.

FirewallTerm is a map from the Erlkoenig DSL (or empty for defaults):
  #{chains => [#{rules => [...], ...}], sets => [...], counters => [...]}

When FirewallTerm is empty or has no chains, default rules are used
(ct_established + icmp + dns + accept).
""".
-spec add_container(binary(), inet:ip_address(), undefined | binary(),
                    [{non_neg_integer(), non_neg_integer()}],
                    map()) ->
    ok | {error, term()}.
add_container(ContainerId, Ip, HostIface, Ports, FirewallTerm) ->
    add_container(ContainerId, Ip, HostIface, Ports, FirewallTerm, undefined).

-doc "Add container with named chain for readable nft output.".
add_container(_ContainerId, _Ip, HostIface, _Ports, _FirewallTerm, _Name)
  when HostIface =/= undefined ->
    {error, {legacy_host_interface_refused, HostIface}};
add_container(ContainerId, Ip, undefined, Ports, FirewallTerm, Name) ->
    _ = ensure_ets(),
    Chain = chain_name(ContainerId, Name),
    IpBin = ip_to_binary(Ip),
    Rules = rules_from_term(FirewallTerm),

    %% Add counter + nflog to drop rules for observability (SPEC-EK-005)
    DropCounterName = <<Chain/binary, "_drop">>,
    NflogGroup = next_nflog_group(),
    Rules2 = inject_drop_observability(Rules, DropCounterName, NflogGroup),
    RuleMsgs = [nft_encode:rule_fun(inet, ?TABLE, Chain, R) || R <- Rules2],

    SetMsgs = sets_from_term(FirewallTerm),
    CounterMsgs = counters_from_term(FirewallTerm),
    %% Add the drop counter object
    DropCounterMsg = [fun(S) ->
        nft_object:add_counter(?FAMILY, ?TABLE, DropCounterName, S)
    end],

    %% Jump rule: dispatch container traffic to its chain.
    %% IPVLAN: IP-based dispatch (outbound=saddr, inbound=daddr). The slave
    %% lives in the container netns, so there is no host-side interface to
    %% match in the forward chain.
    JumpMsgs = [
        nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
            nft_rules:ip_saddr_jump(IpBin, Chain)),
        nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
            nft_rules:ip_daddr_jump(IpBin, Chain))
    ],

    Msgs = [
        %% 1. Create regular chain (no hook)
        fun(S) -> nft_chain:add_regular(?FAMILY,
            #{table => ?TABLE, name => Chain}, S) end
    ] ++ SetMsgs ++ CounterMsgs ++ DropCounterMsg ++ RuleMsgs ++ JumpMsgs,

    %% DNAT rules in prerouting (external) + output (local) chains
    NatTable = nat_table(),
    DnatMsgs = lists:append([
        [nft_encode:rule_fun(inet, NatTable, ?PREROUTING_CHAIN,
            nft_rules:tcp_dnat(HostPort, IpBin, ContainerPort)),
         nft_encode:rule_fun(inet, NatTable, ?OUTPUT_CHAIN,
            nft_rules:tcp_dnat(HostPort, IpBin, ContainerPort))]
     || {HostPort, ContainerPort} <- Ports
    ]),

    %% Apply kernel-level config FIRST. Only record in ETS and start the
    %% nflog receiver when the batch committed — otherwise a mid-batch
    %% kernel rejection leaves ETS claiming this container is firewalled
    %% (with chain name X, ports Y) while no chain actually exists.
    %% The next remove_container would then try to flush+delete a chain
    %% that was never created and rebuild jump/DNAT rules that refer to
    %% a nonexistent target — cascading kernel ENOENT errors.
    Result = nfnl_server:apply_msgs(?SERVER, Msgs ++ DnatMsgs),
    case Result of
        ok ->
            ets:insert(erlkoenig_firewall_ports,
                       {ContainerId, undefined, Ip, Ports, Chain}),
            case erlkoenig_nft_nflog:start_link(NflogGroup) of
                {ok, _} ->
                    logger:info("erlkoenig_ct_firewall: nflog group ~p for ~s",
                                [NflogGroup, Chain]);
                {error, Reason} ->
                    logger:warning("erlkoenig_ct_firewall: nflog start failed "
                                   "for ~s: ~p",
                                   [Chain, Reason])
            end;
        {error, ApplyReason} ->
            logger:warning("erlkoenig_ct_firewall: add_container ~s batch "
                           "failed: ~p (ETS + nflog left untouched)",
                           [Chain, ApplyReason])
    end,
    Result.

-doc """
Remove all firewall rules for a container.

Flushes all shared chains (forward, prerouting, output), deletes
the container chain, then rebuilds shared-chain rules for all
remaining containers.
""".
-spec remove_container(binary()) -> ok | {error, term()}.
remove_container(ContainerId) ->
    global:trans({?MODULE, remove_container},
                 fun() -> remove_container_locked(ContainerId) end,
                 [node()], infinity).

-spec remove_container_locked(binary()) -> ok | {error, term()}.
remove_container_locked(ContainerId) ->
    _ = ensure_ets(),
    %% No ETS entry means add_container never committed kernel state for this
    %% container, so cleanup is idempotently complete. Guessing a chain name
    %% here turns normal no-firewall containers into noisy ENOENT warnings.
    case ets:lookup(erlkoenig_firewall_ports, ContainerId) of
        [] ->
            ok;
        [{_, _LegacyHostIface, _Ip, Ports, Chain}] ->
            remove_container_entry(ContainerId, Chain, Ports);
        [{_, _, _, Ports}] ->
            remove_container_entry(ContainerId, chain_name(ContainerId), Ports)
    end.

-spec remove_container_entry(binary(), binary(), list()) -> ok | {error, term()}.
remove_container_entry(ContainerId, Chain, Ports) ->
    %% Build the "remaining containers" snapshot from the ETS state WITHOUT
    %% mutating it yet. Mirrors the fix in add_container: if the kernel
    %% batch is rejected, we must not have deleted ETS first — that would
    %% leave kernel rules for this container live while ETS claims it's
    %% gone, and future rebuilds would miss those orphaned rules forever.
    Remaining = [R || R <- ets:tab2list(erlkoenig_firewall_ports),
                      is_tuple(R), tuple_size(R) =:= 5,
                      element(1, R) =/= ContainerId],
    RemoveResult = nfnl_server:apply_msgs(?SERVER,
        build_remove_target_msgs(Chain, Ports)),
    CounterResult = case RemoveResult of
        ok ->
            nfnl_server:apply_msgs(?SERVER, build_remove_counter_msgs(Chain));
        {error, _} = RemoveErr ->
            RemoveErr
    end,
    RebuildResult = case RemoveResult of
        ok ->
            nfnl_server:apply_msgs(?SERVER, build_rebuild_shared_msgs(Remaining));
        {error, _} = RemoveErr2 ->
            RemoveErr2
    end,
    case {RemoveResult, CounterResult, RebuildResult} of
        {ok, ok, ok} ->
            ets:delete(erlkoenig_firewall_ports, ContainerId),
            ok;
        {ok, {error, CounterReason}, ok} ->
            ets:delete(erlkoenig_firewall_ports, ContainerId),
            logger:warning("erlkoenig_ct_firewall: remove_container ~s counter "
                           "delete failed after chain cleanup: ~p",
                           [Chain, CounterReason]),
            {error, {counter_delete_failed, CounterReason}};
        {ok, _, {error, RebuildReason}} ->
            logger:warning("erlkoenig_ct_firewall: remove_container ~s shared "
                           "rebuild failed: ~p (ETS entry retained)",
                           [Chain, RebuildReason]),
            {error, {shared_rebuild_failed, RebuildReason}};
        {{error, RemoveReason}, _, _} ->
            logger:warning("erlkoenig_ct_firewall: remove_container ~s target "
                           "cleanup failed: ~p (ETS entry retained so a retry "
                           "can target the same chain)",
                           [Chain, RemoveReason]),
            {error, RemoveReason}
    end.

-ifdef(TEST).
-spec build_remove_msgs(binary(), list(), [tuple()]) -> [fun()].
build_remove_msgs(Chain, Ports, Remaining) ->
    %% 1. Flush shared chains + container chain, then delete container chain.
    %%    Forward + per-container chains live in forward_table, NAT
    %%    chains in nat_table. NAT chains are only touched when this
    %%    container installed DNAT rules; flushing an empty NAT chain can make
    %%    the kernel reject the entire transaction with ENOENT and leak the
    %%    container chain.
    build_remove_target_msgs(Chain, Ports)
    ++ build_remove_counter_msgs(Chain)
    ++ build_rebuild_shared_msgs(Remaining).
-endif.

-spec build_remove_target_msgs(binary(), list()) -> [fun()].
build_remove_target_msgs(Chain, Ports) ->
    FwdTable = forward_table(),
    [
        fun(S) -> nft_delete:flush_chain(?FAMILY, FwdTable, ?FORWARD_CHAIN, S) end
    ] ++ nat_flush_msgs(Ports)
      ++ [
        fun(S) -> nft_delete:flush_chain(?FAMILY, FwdTable, Chain, S) end,
        fun(S) -> nft_delete:chain(?FAMILY, FwdTable, Chain, S) end
    ].

-spec build_remove_counter_msgs(binary()) -> [fun()].
build_remove_counter_msgs(Chain) ->
    FwdTable = forward_table(),
    [
        fun(S) -> nft_object:delete(?FAMILY, FwdTable, <<Chain/binary, "_drop">>, S) end
    ].

-spec build_rebuild_shared_msgs([tuple()]) -> [fun()].
build_rebuild_shared_msgs(Remaining) ->
    FwdTable = forward_table(),
    BaseMsgs = [
        nft_encode:rule_fun(inet, FwdTable, ?FORWARD_CHAIN,
            nft_rules:ct_established_accept())
    ],
    RebuildMsgs = lists:append([rebuild_shared_rules(R) || R <- Remaining]),
    BaseMsgs ++ RebuildMsgs.

nat_flush_msgs([]) ->
    [];
nat_flush_msgs(_Ports) ->
    NatTable = nat_table(),
    [
        fun(S) -> nft_delete:flush_chain(?FAMILY, NatTable, ?PREROUTING_CHAIN, S) end,
        fun(S) -> nft_delete:flush_chain(?FAMILY, NatTable, ?OUTPUT_CHAIN, S) end
    ].

-doc "Rebuild forward jump + DNAT rules for one container.".
-spec rebuild_shared_rules(tuple()) -> [fun()].
rebuild_shared_rules({_Id, _LegacyHostIface, Ip, [], Chain2}) ->
    IpBin = ip_to_binary(Ip),
    [nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
        nft_rules:ip_saddr_jump(IpBin, Chain2)),
     nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
        nft_rules:ip_daddr_jump(IpBin, Chain2))];
rebuild_shared_rules({_Id, _LegacyHostIface, Ip, Ports, Chain2}) ->
    IpBin = ip_to_binary(Ip),
    [nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
        nft_rules:ip_saddr_jump(IpBin, Chain2)),
     nft_encode:rule_fun(inet, ?TABLE, ?FORWARD_CHAIN,
        nft_rules:ip_daddr_jump(IpBin, Chain2))] ++
    rebuild_port_forwards(Ip, Ports).

%% Port-forward rules only.
-spec rebuild_port_forwards(inet:ip_address(), [{non_neg_integer(), non_neg_integer()}]) -> [fun()].
rebuild_port_forwards(Ip, Ports) ->
    IpBin = ip_to_binary(Ip),
    NatTable = nat_table(),
    lists:append([
        [nft_encode:rule_fun(inet, NatTable, ?PREROUTING_CHAIN,
            nft_rules:tcp_dnat(HP, IpBin, CP)),
         nft_encode:rule_fun(inet, NatTable, ?OUTPUT_CHAIN,
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

-spec pad_ifname(binary()) -> binary().
pad_ifname(Name) when byte_size(Name) =< 16 ->
    Pad = 16 - byte_size(Name),
    <<Name/binary, 0:(Pad * 8)>>.

%% Named chain: use container name for readable nft output.
%% "web-0-nginx" → "web-0-nginx" (nft chain name)
-spec chain_name(binary()) -> binary().
chain_name(ContainerId) ->
    Short = binary:part(ContainerId, 0, min(12, byte_size(ContainerId))),
    <<"ct_", Short/binary>>.

-spec chain_name(binary(), binary() | undefined) -> binary().
chain_name(_ContainerId, Name) when is_binary(Name), Name =/= <<>> ->
    Name;
chain_name(ContainerId, _) ->
    chain_name(ContainerId).

-spec ip_to_binary(inet:ip_address()) -> binary().
ip_to_binary({A, B, C, D}) ->
    <<A, B, C, D>>;
ip_to_binary({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

%% Convert IP in any format to 4-byte binary.
%% Handles: <<10,0,0,1>> (already binary), <<"10.0.0.1">> (string), {10,0,0,1} (tuple)
-spec ensure_ip_binary(binary() | tuple()) -> binary().
ensure_ip_binary(<<A, B, C, D>>) when byte_size(<<A,B,C,D>>) =:= 4, A < 256 ->
    %% Could be 4-byte IP or start of a string like "10.0"
    %% If all bytes are < 256 and no dots, treat as raw IP
    case binary:match(<<A,B,C,D>>, <<".">>) of
        nomatch -> <<A, B, C, D>>;
        _ -> parse_ip_string(<<A,B,C,D>>)
    end;
ensure_ip_binary(Bin) when is_binary(Bin) ->
    parse_ip_string(Bin);
ensure_ip_binary({A, B, C, D}) ->
    <<A, B, C, D>>;
ensure_ip_binary(Other) ->
    ip_to_binary(Other).

parse_ip_string(Bin) ->
    case inet:parse_address(binary_to_list(Bin)) of
        {ok, {A, B, C, D}} -> <<A, B, C, D>>;
        _ -> Bin
    end.

to_binary(B) when is_binary(B) -> B;
to_binary(A) when is_atom(A) -> atom_to_binary(A);
to_binary(L) when is_list(L) -> iolist_to_binary(L).

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

%% Inject counter + nflog into drop rules for observability.
%% Counter counts drops, NFLOG sends packet details to userspace.
-spec inject_drop_counter([list()], binary()) -> [list()].
inject_drop_counter(CompiledRules, CounterName) ->
    inject_drop_observability(CompiledRules, CounterName, undefined).

-spec inject_drop_observability([list()], binary(), non_neg_integer() | undefined) -> [list()].
inject_drop_observability(CompiledRules, CounterName, NflogGroup) ->
    lists:map(fun(Exprs) ->
        case has_drop_verdict(Exprs) of
            true ->
                inject_before_verdict(Exprs, CounterName, NflogGroup);
            false ->
                Exprs
        end
    end, CompiledRules).

has_drop_verdict([]) -> false;
has_drop_verdict([{immediate, #{verdict := drop}} | _]) -> true;
has_drop_verdict([_ | Rest]) -> has_drop_verdict(Rest).

inject_before_verdict([], _, _) -> [];
inject_before_verdict([{immediate, #{verdict := drop}} = Drop | Rest], CounterName, NflogGroup) ->
    Counter = [nft_expr_ir:objref_counter(CounterName)],
    Nflog = case NflogGroup of
        undefined -> [];
        Group -> [nft_expr_ir:log(#{group => Group, prefix => CounterName})]
    end,
    Counter ++ Nflog ++ [Drop | Rest];
inject_before_verdict([Expr | Rest], CounterName, NflogGroup) ->
    [Expr | inject_before_verdict(Rest, CounterName, NflogGroup)].

%% NFLOG group allocator — base 100, incrementing per container.
-define(NFLOG_BASE_GROUP, 100).

next_nflog_group() ->
    ensure_ets(),
    try
        ets:update_counter(erlkoenig_firewall_ports, nflog_group_counter, 1)
    catch
        error:badarg ->
            ets:insert(erlkoenig_firewall_ports, {nflog_group_counter, ?NFLOG_BASE_GROUP}),
            ?NFLOG_BASE_GROUP
    end.

-doc """
Return the NFLOG group reserved for the given zone, allocating one
on first use. Idempotent across reloads — the second call for the
same zone returns the same group, so the matching nflog receiver
can be re-used via `erlkoenig_nft_nflog:ensure_started/1' instead
of leaking a new gen_server per `apply_zone_chains/2' call.
""".
-spec nflog_group_for_zone(binary()) -> non_neg_integer().
nflog_group_for_zone(ZoneName) when is_binary(ZoneName) ->
    ensure_ets(),
    Key = {zone_nflog, ZoneName},
    case ets:lookup(erlkoenig_firewall_ports, Key) of
        [{_, Group}] ->
            Group;
        [] ->
            Group = next_nflog_group(),
            case ets:insert_new(erlkoenig_firewall_ports, {Key, Group}) of
                true ->
                    Group;
                false ->
                    %% Concurrent caller won the race; their group wins.
                    [{_, Existing}] =
                        ets:lookup(erlkoenig_firewall_ports, Key),
                    Existing
            end
    end.

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
    nft_rules:ip_saddr_accept(ensure_ip_binary(Ip));
compile_rule({ip_saddr_drop, Ip}) ->
    nft_rules:ip_saddr_drop(ensure_ip_binary(Ip));
compile_rule({iifname_accept, Name}) ->
    nft_rules:iifname_accept(iolist_to_binary(Name));
compile_rule({set_lookup_drop, SetName}) ->
    nft_rules:set_lookup_drop(iolist_to_binary(SetName));
compile_rule({set_lookup_drop, SetName, Type}) when Type =:= ipv4_addr; Type =:= ipv6_addr ->
    nft_rules:set_lookup_drop(iolist_to_binary(SetName), Type);
compile_rule({set_lookup_drop, SetName, Counter}) ->
    nft_rules:set_lookup_drop_named(iolist_to_binary(SetName), to_binary(Counter));
compile_rule({set_lookup_drop_named, SetName, Counter, Type}) ->
    nft_rules:set_lookup_drop_named(iolist_to_binary(SetName), to_binary(Counter), Type);
compile_rule({connlimit_drop, Max, Offset}) ->
    nft_rules:connlimit_drop(Max, Offset);
compile_rule({log_drop, Prefix}) ->
    nft_rules:log_drop(iolist_to_binary(Prefix));
compile_rule({log_drop, Prefix, Counter}) ->
    nft_rules:log_drop_named(iolist_to_binary(Prefix), iolist_to_binary(Counter));
compile_rule({log_reject, Prefix}) ->
    nft_rules:log_reject(iolist_to_binary(Prefix));
compile_rule({dnat, Ip, Port}) ->
    nft_rules:tcp_dnat(Port, ensure_ip_binary(Ip), Port);
%% Masquerade
compile_rule(masq) ->
    nft_rules:masq_rule();
compile_rule({oifname_neq_masq, Name}) ->
    nft_rules:oifname_neq_masq(iolist_to_binary(Name));
%% Jump
compile_rule({jump, Chain}) ->
    [nft_expr_ir:jump(iolist_to_binary(Chain))];
%% Conntrack mark
compile_rule({ct_mark_match, Value, Verdict}) ->
    nft_rules:ct_mark_match(Value, Verdict);
compile_rule({ct_mark_set, Value}) ->
    nft_rules:ct_mark_set(Value);
%% Notrack
compile_rule({notrack, Proto, Port}) ->
    nft_rules:notrack_rule(Proto, Port);
%% NFLOG drop
compile_rule({log_drop_nflog, Prefix, Group, Counter}) ->
    nft_rules:log_drop_nflog(iolist_to_binary(Prefix), Group,
                              iolist_to_binary(Counter));
%% oifname accept
compile_rule({oifname_accept, Name}) ->
    nft_rules:oifname_accept(iolist_to_binary(Name));
%% ICMP with counter
compile_rule({icmp_accept_named, Counter}) ->
    nft_rules:icmp_accept_named(iolist_to_binary(Counter));
%% Set lookup accept
compile_rule({set_lookup_accept, SetName}) ->
    nft_rules:set_lookup_accept(iolist_to_binary(SetName));
compile_rule({set_lookup_accept, SetName, Type}) when Type =:= ipv4_addr; Type =:= ipv6_addr ->
    nft_rules:set_lookup_accept(iolist_to_binary(SetName), Type);
compile_rule({set_lookup_accept, SetName, Counter}) ->
    nft_rules:set_lookup_accept_named(iolist_to_binary(SetName),
                                       iolist_to_binary(Counter));
compile_rule({set_lookup_accept_tcp, SetName}) ->
    nft_rules:set_lookup_tcp_accept(iolist_to_binary(SetName));
%% SNAT
compile_rule({snat, Ip}) ->
    nft_rules:snat_rule(ensure_ip_binary(Ip), 0);
compile_rule({snat, Ip, Port}) ->
    nft_rules:snat_rule(ensure_ip_binary(Ip), Port);
%% TCP DNAT (full form)
compile_rule({tcp_dnat, HostPort, Ip, ContainerPort}) ->
    nft_rules:tcp_dnat(HostPort, ensure_ip_binary(Ip), ContainerPort);
%% Vmap dispatch
compile_rule({vmap_dispatch, Proto, VmapName}) ->
    nft_rules:vmap_dispatch(Proto, iolist_to_binary(VmapName));
compile_rule({vmap_dispatch, VmapName}) ->
    nft_rules:vmap_dispatch(tcp, iolist_to_binary(VmapName));
%% FIB
compile_rule(fib_rpf_drop) ->
    nft_rules:fib_rpf_drop();
%% Connlimit (full form)
compile_rule({connlimit_drop, Max}) ->
    nft_rules:connlimit_drop(Max, 0);
%% Flow offload
compile_rule({flow_offload, FlowtableName}) ->
    nft_rules:flow_offload(iolist_to_binary(FlowtableName));

%% Catch-all
compile_rule(Unknown) ->
    logger:warning("erlkoenig_ct_firewall: unknown rule ~p, skipping", [Unknown]),
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
            try
                ets:new(erlkoenig_firewall_ports,
                        [set, named_table, public, {read_concurrency, true}]),
                ok
            catch
                error:badarg ->
                    %% Another process can win the named-table create
                    %% race between whereis/1 and ets:new/2.
                    case ets:whereis(erlkoenig_firewall_ports) of
                        undefined -> error(badarg);
                        _Tid -> ok
                    end
            end;
        _Tid ->
            ok
    end.

%%====================================================================
%% Zone allow directives → nftables rules
%%====================================================================

-doc """
Apply zone-level network policy to the forward chain in
`forward_table()`. This function does not write to the NAT table.

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

%% Interface name matching is exact. Prefix wildcards from the old
%% host-interface model are refused under the IPVLAN runtime.
-spec ifname_match(iifname | oifname, eq | neq, binary()) -> list().
ifname_match(MetaKey, Op, Name) ->
    case binary:match(Name, <<"*">>) of
        nomatch ->
            [nft_expr_ir:meta(MetaKey, 1),
             nft_expr_ir:cmp(Op, 1, pad_ifname(Name))];
        _ ->
            error({legacy_ifname_wildcard_refused,
                   #{field => MetaKey,
                     name => Name,
                     hint => <<"interface wildcards were removed with IPVLAN; "
                               "use exact host interface names or IP matches">>}})
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
            %% Delegate to specific handlers for complex verdict types.
            %% Tagged return shapes:
            %%   {ok, with_matches, Exprs}  — handler already baked in the
            %%       proto/port match (e.g. tcp_reject, notrack_rule,
            %%       tcp_dnat). Use Exprs as-is; prepending Matches would
            %%       duplicate the tcp/udp match. Additional keys like
            %%       saddr/iif that aren't covered by the handler are
            %%       rejected at DSL level (or ignored here).
            %%   {ok, Exprs}                — verdict-only result; the
            %%       caller must prepend generic matches. This is the path
            %%       for snat/fib_rpf/connlimit/vmap_* etc.
            %%   false                      — no special handler; fall
            %%       through to matches + modifiers + verdict pipeline.
            case compile_generic_special(Verdict, Opts) of
                {ok, with_matches, SpecialResult} ->
                    %% Multi-rule (e.g. tcp_accept_limited) and single-rule
                    %% both supported — handler baked in all needed matches.
                    SpecialResult;
                {ok, SpecialResult} ->
                    Matches = compile_generic_matches(Opts),
                    case SpecialResult of
                        [H | _] when is_list(H) ->
                            [Matches ++ R || R <- SpecialResult];
                        _ ->
                            case Matches of
                                [] -> SpecialResult;
                                _  -> Matches ++ SpecialResult
                            end
                    end;
                false ->
                    %% Matches + Modifiers (counter, limit, log) + Verdict
                    Matches = compile_generic_matches(Opts),
                    Mods = compile_generic_modifiers(Opts),
                    V = compile_generic_verdict(Verdict, Opts),
                    Matches ++ Mods ++ V
            end
    end.

%% Handle rule types that need special compilation (not match+modifier+verdict).
%% `{ok, with_matches, ...}` signals that the handler has already emitted
%% proto/port match expressions, so compile_generic_rule must NOT prepend
%% compile_generic_matches — otherwise tcp/udp matches are duplicated.
-spec compile_generic_special(atom(), map()) ->
    {ok, list()} | {ok, with_matches, list()} | false.
compile_generic_special(notrack, #{udp := Port}) ->
    {ok, with_matches, nft_rules:notrack_rule(Port, udp)};
compile_generic_special(notrack, #{tcp := Port}) ->
    {ok, with_matches, nft_rules:notrack_rule(Port, tcp)};
compile_generic_special(ct_mark_set, #{value := Value}) ->
    {ok, nft_rules:ct_mark_set(Value)};
compile_generic_special(ct_mark_match, #{value := Value, verdict := Verdict}) ->
    {ok, nft_rules:ct_mark_match(Value, Verdict)};
compile_generic_special(snat, #{addr := Addr, port := Port}) ->
    {ok, nft_rules:snat_rule(ensure_ip_binary(Addr), Port)};
compile_generic_special(snat, #{addr := Addr}) ->
    {ok, nft_rules:snat_rule(ensure_ip_binary(Addr), 0)};
compile_generic_special(dnat, #{tcp := MatchPort, addr := Addr, dport := DstPort}) ->
    {ok, with_matches, nft_rules:tcp_dnat(MatchPort, ensure_ip_binary(Addr), DstPort)};
compile_generic_special(fib_rpf, _) ->
    {ok, nft_rules:fib_rpf_drop()};
compile_generic_special(connlimit_drop, #{max := Max}) ->
    Flags = 1,
    {ok, nft_rules:connlimit_drop(Max, Flags)};
compile_generic_special(vmap_dispatch, #{proto := Proto, name := Name}) ->
    {ok, nft_rules:vmap_dispatch(Proto, iolist_to_binary(Name))};
compile_generic_special(vmap_concat_lookup, #{set := SetName, fields := Fields} = Opts) ->
    SetId = maps:get(set_id, Opts, 0),
    {ok, nft_rules:concat_vmap_lookup(iolist_to_binary(SetName), Fields, SetId)};
compile_generic_special(accept, #{tcp_range := {From, To}}) ->
    {ok, nft_rules:tcp_port_range_accept(From, To)};
compile_generic_special(accept, #{protocol := Proto}) ->
    {ok, nft_rules:protocol_accept(Proto)};
compile_generic_special(reject, #{tcp := Port}) ->
    {ok, with_matches, nft_rules:tcp_reject(Port)};
compile_generic_special(accept, #{tcp := Port, counter := Counter, limit := #{rate := Rate, burst := Burst}}) ->
    {ok, with_matches, nft_rules:tcp_accept_limited(Port, iolist_to_binary(Counter),
                                                     #{rate => Rate, burst => Burst})};
compile_generic_special(dnat_lb, #{targets := Targets, dport := Port,
                                    map_name := MapName, map_id := MapId})
  when is_list(Targets), length(Targets) > 0 ->
    {ok, nft_rules:dnat_lb_rule(Targets, Port, MapName, MapId)};
compile_generic_special(dnat_jhash, #{map := MapName, dport := Port, mod := Mod}) ->
    MapNameBin = iolist_to_binary(MapName),
    MapId = erlang:phash2(MapNameBin) band 16#FFFF,
    {ok, nft_rules:dnat_jhash_rule(Mod, Port, MapNameBin, MapId)};
compile_generic_special(vmap_lookup, #{vmap := VmapName, type := ifname}) ->
    VmapNameBin = iolist_to_binary(VmapName),
    VmapId = erlang:phash2(VmapNameBin) band 16#FFFF,
    {ok, nft_rules:ifname_vmap_lookup(VmapNameBin, VmapId)};
compile_generic_special(vmap_lookup, #{vmap := VmapName, fields := Fields}) ->
    VmapNameBin = iolist_to_binary(VmapName),
    VmapId = erlang:phash2(VmapNameBin) band 16#FFFF,
    {ok, nft_rules:concat_vmap_lookup(VmapNameBin, Fields, VmapId)};
compile_generic_special(vmap_lookup, #{vmap := VmapName}) ->
    VmapNameBin = iolist_to_binary(VmapName),
    VmapId = erlang:phash2(VmapNameBin) band 16#FFFF,
    {ok, nft_rules:concat_vmap_lookup(VmapNameBin,
        [ip_saddr, ip_daddr, tcp_dport], VmapId)};
compile_generic_special(_, _) -> false.

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
compile_match_saddr(#{saddr := IpStr}) when is_binary(IpStr); is_list(IpStr) ->
    Ip = ensure_ip_binary(IpStr),
    {true, [nft_expr_ir:meta(nfproto, 1),
            nft_expr_ir:cmp(eq, 1, <<2>>),
            nft_expr_ir:ip_saddr(1),
            nft_expr_ir:cmp(eq, 1, Ip)]};
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

compile_match_set(#{set := SetName, set_type := ipv6_addr}) ->
    SetBin = iolist_to_binary(SetName),
    {true, [nft_expr_ir:meta(nfproto, 1),
            nft_expr_ir:cmp(eq, 1, <<10>>),
            nft_expr_ir:ip6_saddr(1),
            nft_expr_ir:lookup(1, SetBin)]};
compile_match_set(#{set := SetName}) ->
    SetBin = iolist_to_binary(SetName),
    {true, [nft_expr_ir:meta(nfproto, 1),
            nft_expr_ir:cmp(eq, 1, <<2>>),
            nft_expr_ir:ip_saddr(1),
            nft_expr_ir:lookup(1, SetBin)]};
compile_match_set(_) -> false.


-spec compile_generic_modifiers(map()) -> list().
compile_generic_modifiers(Opts) ->
    %% Order: log, counter, limit (matches nft_rules convention)
    Mods = [],
    Mods1 = case maps:find(log, Opts) of
        {ok, Prefix} when is_binary(Prefix); is_list(Prefix) ->
            Mods ++ [nft_expr_ir:log(#{prefix => iolist_to_binary(Prefix)})];
        {ok, #{prefix := Prefix, group := Group}} ->
            Mods ++ [nft_expr_ir:log(#{prefix => iolist_to_binary(Prefix), group => Group})];
        _ -> Mods
    end,
    Mods2 = case maps:find(counter, Opts) of
        {ok, Name} -> Mods1 ++ [nft_expr_ir:objref_counter(iolist_to_binary(Name))];
        _ -> Mods1
    end,
    Mods3 = case maps:find(limit, Opts) of
        {ok, #{rate := Rate, burst := Burst}} ->
            Mods2 ++ [nft_expr_ir:limit(Rate, Burst)];
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
