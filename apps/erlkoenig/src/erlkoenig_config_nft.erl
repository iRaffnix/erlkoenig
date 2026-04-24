%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_config_nft).
-moduledoc """
DSL-to-kernel nftables compilation.

Takes the parsed DSL config (after zones exist and containers
have spawned) and produces the atomic netlink batches that
realise host nft_tables, zone forward rules and pod-local
forward chains in the kernel.

Major concerns in this module:

  * **Name ↔ IP plumbing.**
    `build_veth_map/1' + `parse_container_name/1' + the
    `find_digit_segment/2' / `is_all_digits/1' helpers recover
    {Pod, Ct} from the `<Pod>-<ReplicaIdx>-<Ct>' naming
    convention. `build_replica_ip_map/3' inverts the
    name→IP map into a {Pod, Ct} → [IP] map for replica_ips
    expansion.

  * **Host nft_tables apply.**
    `apply_nft_tables/5' + `apply_nft_table/3' build a single
    atomic batch per table: counters + sets + flowtables +
    map/vmap creates + chains + map/vmap elements + rules.
    Selective cleanup diffs against a persistent_term record
    of DSL-owned object names so a reload doesn't wipe
    sibling-subsystem state.

  * **Set / map / vmap compilation.**
    `compile_set_msg/3', `compile_explicit_map/4',
    `compile_explicit_vmap/5', `resolve_map_entries/4',
    `resolve_vmap_entries/3', `normalize_map_key/2',
    `vmap_field_to_bin/1', `verdict_atom/1', `vmap_key/2',
    `resolve_vmap_key/3', `nft_type_atom_to_int/1',
    `nft_type_len/1'.

  * **Rule expansion.**
    `expand_nft_rule/4' is the Glasbox seam for
    `{veth_of, _, _}' and `{replica_ips, _, _}' references —
    unresolved refs become `__unresolved__' placeholders that
    `expanded_rule_has_unresolved/1' filters before the batch,
    so the atomic transaction still lands for the rest of the
    chain. History in the function body: every behaviour here
    is there to prevent a Glasbox silent-widening (bugs
    #75-78 from the audit sweep).

  * **Zone chain apply.**
    `apply_zone_chains/2' + `resolve_host_refs/2' +
    `find_all_replica_ips/3' + `expand_pod_ref_rules/3'
    translate the zone-scoped rule terms into nft_tables
    rules in the shared `erlkoenig' table.

  * **Pod-local forward chains.**
    `apply_pod_forward_chains/3' +
    `apply_pod_chains_for_replicas/5' +
    `resolve_and_compile_rule/4' + `resolve_ref_ip/3' +
    `has_unresolved/1' + `expanded_rule_has_unresolved/1'
    handle the legacy pod-level chains path.

The public entry points `apply_nft_tables/5',
`expand_nft_rule/4', `parse_container_name/1',
`resolve_host_refs/2' and `find_all_replica_ips/3' stay
reachable via `erlkoenig_config' wrappers so existing callers
(the host-apply flow, fuzz tests, the `ek' CLI) don't have to
change.
""".

-export([
    %% Name ↔ IP
    build_veth_map/1,
    parse_container_name/1,
    build_replica_ip_map/3,
    %% Host nft_tables apply
    apply_nft_tables/5,
    apply_nft_table/3,
    %% Rule expansion
    expand_nft_rule/4,
    %% Zone chains
    apply_zone_chains/2,
    resolve_host_refs/2,
    find_all_replica_ips/3,
    %% Pod forward chains
    apply_pod_forward_chains/3
]).

%% =================================================================
%% Name ↔ IP plumbing
%% =================================================================

%% Build {PodName, ContainerName} → HostVeth map from spawned containers.
-spec build_veth_map([{binary(), pid()}]) -> map().
build_veth_map(Results) ->
    lists:foldl(fun({Name, Pid}, Acc) ->
        try erlkoenig:inspect(Pid) of
            #{net_info := #{host_veth := Veth}} ->
                %% Name = "web-0-nginx" → extract pod="web", ct="nginx"
                case parse_container_name(Name) of
                    {Pod, _Idx, Ct} -> Acc#{{Pod, Ct} => Veth};
                    _ -> Acc
                end;
            _ -> Acc
        catch _:_ -> Acc
        end
    end, #{}, Results).

%% Parse the canonical "<Pod>-<ReplicaIdx>-<Ct>" name back into parts.
%%
%% `expand_container_replicas/4' always writes the replica index as a
%% pure-integer decimal token in the middle position, so we locate the
%% split by scanning for the first all-digit segment. The naive "first
%% dash" + "last dash" approach previously broke any pod or container
%% name that itself contained a dash:
%%
%%   "my-web-0-nginx"       → pod="my", ct="nginx", idx="web-0"  (WRONG pod)
%%   "web-0-nginx-plus"     → pod="web", ct="plus", idx="0-nginx" (WRONG ct)
%%
%% Both cases meant VethMap and ReplicaIpMap got bogus keys and every
%% downstream {veth_of, Pod, Ct} or {replica_ips, Pod, Ct} lookup
%% silently fell to the unresolved path.
-spec parse_container_name(binary()) -> {binary(), binary(), binary()} | error.
parse_container_name(Name) ->
    Parts = binary:split(Name, <<"-">>, [global]),
    case find_digit_segment(Parts, []) of
        {PodParts, Idx, CtParts}
          when PodParts =/= [], CtParts =/= [] ->
            {iolist_to_binary(lists:join(<<"-">>, PodParts)),
             Idx,
             iolist_to_binary(lists:join(<<"-">>, CtParts))};
        _ ->
            error
    end.

%% Walk the parts list picking the first all-digit segment as the
%% replica index; everything before is pod, everything after is ct.
-spec find_digit_segment([binary()], [binary()]) ->
    {[binary()], binary(), [binary()]} | error.
find_digit_segment([], _Acc) ->
    error;
find_digit_segment([P | Rest], Acc) ->
    case is_all_digits(P) of
        true ->
            {lists:reverse(Acc), P, Rest};
        false ->
            find_digit_segment(Rest, [P | Acc])
    end.

-spec is_all_digits(binary()) -> boolean().
is_all_digits(<<>>) -> false;
is_all_digits(Bin) ->
    lists:all(fun(C) -> C >= $0 andalso C =< $9 end,
              binary_to_list(Bin)).

%% Build {PodName, ContainerName} → [IP, ...] map for replica expansion.
-spec build_replica_ip_map(map(), [map()], [map()]) -> map().
build_replica_ip_map(IpMap, _Pods, _Zones) ->
    %% IpMap: "web-0-nginx" → {10,0,0,2}
    %% We need: {"web","nginx"} → [{10,0,0,2}, {10,0,0,3}, ...]
    maps:fold(fun(Name, Ip, Acc) ->
        case parse_container_name(Name) of
            {Pod, _Idx, Ct} ->
                Key = {Pod, Ct},
                maps:update_with(Key, fun(Ips) -> Ips ++ [Ip] end, [Ip], Acc);
            _ -> Acc
        end
    end, #{}, IpMap).

%% =================================================================
%% Host nft_tables apply
%% =================================================================

%% Apply nft_tables from the DSL config.
-spec apply_nft_tables([map()], map(), map(), [map()], [map()]) -> ok.
apply_nft_tables([], _, _, _, _) -> ok;
apply_nft_tables(Tables, IpMap, VethMap, Pods, Zones) ->
    ReplicaIpMap = build_replica_ip_map(IpMap, Pods, Zones),
    lists:foreach(fun(Table) ->
        apply_nft_table(Table, VethMap, ReplicaIpMap)
    end, Tables).

apply_nft_table(#{name := TableName, chains := Chains} = Table, VethMap, ReplicaIpMap) ->
    Family = maps:get(family, Table, inet),
    FamilyNum = case Family of inet -> 1; ip -> 2; ip6 -> 10; _ -> 1 end,
    TableBin = iolist_to_binary(TableName),
    Counters = maps:get(counters, Table, []),

    %% 0. Ensure the table exists (idempotent).
    %% Do NOT delete+recreate the table — that wipes chains/sets/maps
    %% from other subsystems (erlkoenig_ct_firewall, ct_guard).
    %% Instead, selectively remove only DSL-owned objects, then re-add.
    _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
        fun(S) -> nft_table:add(FamilyNum, TableBin, S) end
    ]),

    %% 1. Build the new state first (we need map names to know what to delete)
    %% Regular chains first (jump targets), then base chains
    OrderedChains = lists:sort(fun(A, _B) ->
        not maps:is_key(hook, A)
    end, Chains),
    %% Compile all chains → {ChainCreates, MapCreates, RuleCreates}
    {AllChainCreates, AllMapCreates, AllRuleCreates} = lists:foldl(
        fun(Chain, {CAcc, MAcc, RAcc}) ->
            {ChainMsg, MapMsgs, RuleMsgs} = compile_nft_chain_split(
                FamilyNum, TableBin, Chain, VethMap, ReplicaIpMap),
            {CAcc ++ ChainMsg, MAcc ++ MapMsgs, RAcc ++ RuleMsgs}
        end, {[], [], []}, OrderedChains),

    %% 2. Collect names of DSL objects for selective cleanup.
    ChainNames = [iolist_to_binary(maps:get(name, C)) || C <- Chains],
    ExplicitMapNames = [iolist_to_binary(maps:get(name, M))
                        || M <- maps:get(maps, Table, [])],
    ExplicitVmapNames = [iolist_to_binary(maps:get(name, V))
                         || V <- maps:get(vmaps, Table, [])],
    ExplicitSetNames = [iolist_to_binary(set_name(S))
                        || S <- maps:get(sets, Table, [])],
    NewMapNames = ExplicitMapNames ++ ExplicitVmapNames,
    NewSetNames = ExplicitSetNames,
    OldMapNames = persistent_term:get({erlkoenig_dsl_maps, TableBin}, []),
    OldSetNames = persistent_term:get({erlkoenig_dsl_sets, TableBin}, []),

    %% 4. Selectively delete old DSL objects.
    %% Order: flush chain rules → delete chains → delete maps/sets.
    %% Sets/maps cannot be deleted while rules reference them.
    %% Each operation is a separate batch because non-existent objects
    %% cause the whole batch to fail with enoent (first load: nothing exists).
    lists:foreach(fun(CN) ->
        _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_delete:flush_chain(FamilyNum, TableBin, CN, S) end
        ]),
        _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_delete:chain(FamilyNum, TableBin, CN, S) end
        ])
    end, ChainNames),
    AllMapNames = lists:usort(OldMapNames ++ NewMapNames),
    lists:foreach(fun(MN) ->
        _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_delete:set(FamilyNum, TableBin, MN, S) end
        ])
    end, AllMapNames),
    %% Only delete sets that are going away; active DSL sets are preserved
    %% so their elements (added by threat_actor, etc.) survive a reload.
    StaleSetNames = OldSetNames -- NewSetNames,
    lists:foreach(fun(SN) ->
        _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_delete:set(FamilyNum, TableBin, SN, S) end
        ])
    end, StaleSetNames),

    %% NOTE: persistent_term update for NewMapNames/NewSetNames now
    %% happens AFTER the atomic batch below succeeds (see end of
    %% this function). Previously this `put' ran before apply_msgs,
    %% so a kernel-rejected batch left the persistent_term claiming
    %% the new DSL state was live — next reload would try to clean
    %% up stale entries that didn't exist and skip cleaning entries
    %% that did. Same ETS/kernel-drift class we fixed in
    %% erlkoenig_ct_firewall's add_container / remove_container.

    %% 4. Create counters (idempotent — CREATE flag means no error if exists)
    CounterMsgs = [fun(S) ->
        nft_object:add_counter(FamilyNum, TableBin, iolist_to_binary(C), S)
    end || C <- Counters],

    %% 4a. Create sets (declared via nft_set). Must exist before any rule
    %% references them via `set:' lookup, otherwise the batch fails with
    %% ENOENT. Supports 2-tuple {Name, Type} and 3-tuple {Name, Type, Opts}
    %% forms (Opts may carry flags like [timeout] and an initial timeout).
    %% Each DSL set can emit 1-2 batch messages (create + optional
    %% element-add), so flatmap rather than comprehend.
    SetMsgs = lists:flatmap(
        fun(SetDef) -> compile_set_msg(FamilyNum, TableBin, SetDef) end,
        maps:get(sets, Table, [])),

    %% 4a-ft. Create flowtables (declared via nft_flowtable).
    %% Must exist before any rule references them via flow_offload.
    FlowtableMsgs = [fun(S) ->
        nft_flowtable:add(FamilyNum, #{
            table => TableBin,
            name => iolist_to_binary(maps:get(name, Ft)),
            hook => maps:get(hook, Ft, ingress),
            priority => maps:get(priority, Ft, 0),
            devices => [iolist_to_binary(D) || D <- maps:get(devices, Ft, [])]
        }, S)
    end || Ft <- maps:get(flowtables, Table, [])],

    %% 4b. Compile explicit maps (nft_map) from DSL
    ExplicitMaps = maps:get(maps, Table, []),
    ExplicitMapMsgs = lists:flatmap(fun(M) ->
        compile_explicit_map(FamilyNum, TableBin, M, ReplicaIpMap)
    end, ExplicitMaps),

    %% 4c. Compile explicit vmaps (nft_vmap) from DSL
    ExplicitVmaps = maps:get(vmaps, Table, []),
    ExplicitVmapMsgs = lists:flatmap(fun(V) ->
        compile_explicit_vmap(FamilyNum, TableBin, V, VethMap, ReplicaIpMap)
    end, ExplicitVmaps),

    %% 5. Single atomic batch.
    %% Order matters for intra-batch references:
    %%   1. Counters (idempotent, no deps)
    %%   2. Map/VMap creation (NEWSET — must exist before rules reference them)
    %%   3. Chains (must exist before jump verdicts in vmap elements)
    %%   4. Map/VMap elements (NEWSETELEM — jump verdicts need chains, SET_ID links to maps)
    %%   5. Rules (lookup expressions reference maps/vmaps by SET_ID)
    {VmapCreates, VmapElems} = split_create_elems(ExplicitVmapMsgs),
    {MapCreates, MapElems} = split_create_elems(ExplicitMapMsgs),
    AllMsgs = CounterMsgs
        ++ SetMsgs
        ++ FlowtableMsgs
        ++ MapCreates ++ VmapCreates ++ AllMapCreates
        ++ AllChainCreates
        ++ MapElems ++ VmapElems
        ++ AllRuleCreates,
    logger:notice("erlkoenig_config: nft_table ~s: ~p counters, ~p sets, "
                  "~p maps, ~p chains, ~p rules",
                [TableName, length(CounterMsgs), length(SetMsgs),
                 length(AllMapCreates), length(AllChainCreates),
                 length(AllRuleCreates)]),
    case AllMsgs of
        [] ->
            logger:info("erlkoenig_config: nft_table ~s: empty (no chains)", [TableName]);
        _ ->
            case nfnl_server:apply_msgs(erlkoenig_nft_srv, AllMsgs) of
                ok ->
                    %% Commit the new DSL-object inventory AFTER the
                    %% kernel confirmed the batch. If we had done this
                    %% before the batch and the batch failed, the next
                    %% reload would compute stale-set diffs against a
                    %% lie and either orphan old objects or try to
                    %% delete nonexistent ones.
                    persistent_term:put({erlkoenig_dsl_maps, TableBin},
                                        NewMapNames),
                    persistent_term:put({erlkoenig_dsl_sets, TableBin},
                                        NewSetNames),
                    logger:notice("erlkoenig_config: nft_table ~s applied ok", [TableName]),
                    erlkoenig_events:notify({firewall_applied, TableName});
                {error, Reason} ->
                    logger:warning("erlkoenig_config: nft_table ~s batch failed: ~p",
                                   [TableName, Reason]),
                    erlkoenig_events:notify({firewall_failed, TableName, Reason})
            end
    end;
apply_nft_table(_, _, _) -> ok.

%% =================================================================
%% Set / map / vmap compilation
%% =================================================================

%% Extract the name from a DSL set definition.
set_name({Name, _Type})       -> Name;
set_name({Name, _Type, _Opts}) -> Name.

%% Build nft_set:add + (if declared) nft_set_elem:add msgs for one
%% DSL set definition.  Returns a LIST of message-builder funs so
%% the caller can flat-append into the batch.
compile_set_msg(Family, Table, {Name, Type}) ->
    %% No opts → no elements, just create the set.
    [fun(S) -> nft_set:add(Family, #{
        table => Table,
        name  => iolist_to_binary(Name),
        type  => Type
    }, S) end];
compile_set_msg(Family, Table, {Name, Type, Opts}) when is_map(Opts) ->
    NameBin = iolist_to_binary(Name),
    Flags = maps:get(flags, Opts, []),
    Base = #{table => Table, name => NameBin, type => Type, flags => Flags},
    Full = case maps:find(timeout, Opts) of
        {ok, T} -> Base#{timeout => T};
        error   -> Base
    end,
    CreateFun = fun(S) -> nft_set:add(Family, Full, S) end,

    %% Populate declared `elements:' into the set. Previously the
    %% caller built the create-fun and silently dropped the
    %% elements, leaving operators with an empty set — the exact
    %% Glasbox violation we found in tutorial 03 (trusted_cidrs had
    %% 4 CIDRs declared, 0 in kernel).
    Elements = maps:get(elements, Opts, []),
    ElemFuns =
        case {Elements, lists:member(interval, Flags)} of
            {[], _} ->
                [];
            {Es, true} ->
                Ranges = [parse_cidr_range_strict(E) || E <- Es],
                [fun(S) ->
                    nft_set_elem:add_range_elems(Family, Table,
                                                  NameBin, Ranges, S)
                 end];
            {Es, false} ->
                Keys = normalize_plain_elements(Es, Type),
                [fun(S) ->
                    nft_set_elem:add_elems(Family, Table, NameBin, Keys, S)
                 end]
        end,
    [CreateFun | ElemFuns].

%% Fail-loud parser for CIDR set elements.  DSL validation should
%% catch bad input at compile time; silently ignoring a bad element
%% here would leave the operator with an incomplete allowlist.
parse_cidr_range_strict(E) ->
    case erlkoenig_nft_ip:parse_cidr4(E) of
        {ok, Range} -> Range;
        {error, R}  -> error({bad_cidr_element, E, R})
    end.

normalize_plain_elements(Es, Type) when Type =:= ipv4_addr;
                                         Type =:= ipv6_addr ->
    [begin {ok, B} = erlkoenig_nft_ip:normalize(E), B end || E <- Es];
normalize_plain_elements(Es, inet_service) ->
    [<<Port:16/big>> || Port <- Es];
normalize_plain_elements(Es, _) ->
    Es.

compile_nft_chain_split(Family, Table, #{name := Name, rules := Rules} = Chain,
                        VethMap, ReplicaIpMap) ->
    ChainBin = iolist_to_binary(Name),

    %% Create chain (base or regular)
    ChainMsg = case maps:find(hook, Chain) of
        {ok, Hook} ->
            Type = maps:get(type, Chain, filter),
            Priority = priority_to_int(maps:get(priority, Chain, filter)),
            Policy = maps:get(policy, Chain, accept),
            [fun(S) -> nft_chain:add(Family, #{
                table => Table, name => ChainBin,
                hook => Hook, type => Type,
                priority => Priority, policy => Policy
            }, S) end];
        error ->
            [fun(S) -> nft_chain:add_regular(Family, #{
                table => Table, name => ChainBin
            }, S) end]
    end,

    %% Expand all rules (resolve veth_of, replica_ips)
    AllExpanded0 = lists:flatmap(fun({Action, Opts}) ->
        expand_nft_rule(Action, Opts, VethMap, ReplicaIpMap)
    end, Rules),
    %% Filter out rules that carry an `__unresolved__' placeholder —
    %% generated by `expand_nft_rule' when a `replica_ips'/`veth_of'
    %% reference resolves to nothing at apply time (e.g. parallel pod
    %% bring-up). Keeping them would either (a) send a literal
    %% `__unresolved__' binary as an IP/iface to the kernel and get
    %% the whole atomic batch rolled back — wiping the chain itself
    %% and producing the "No such file or directory" the operator
    %% sees on `nft list chain', or (b) silently match nothing if the
    %% kernel happened to accept the bytes. The DSL guarantee is:
    %% rules with an unresolvable ref become no-ops, logged once, and
    %% the rest of the chain still lands so the rest of the policy
    %% stays enforceable.
    AllExpanded =
        [R || R <- AllExpanded0, not expanded_rule_has_unresolved(R)],

    %% Compile rules — no implicit collapsing, no auto-generated maps.
    %% Maps and vmaps are created explicitly from DSL nft_map/nft_vmap blocks.
    %%
    %% Some rule builders (e.g. tcp_accept_limited) return MULTIPLE rules
    %% as [[expr1], [expr2]]. Detect this and produce one rule_fun per sub-rule.
    {RuleMsgs, MapMsgs} = lists:foldl(fun(Rule, {RA, MA}) ->
        try
            Compiled = erlkoenig_ct_firewall:compile_rule(Rule),
            NewMsgs = case Compiled of
                [H | _] when is_list(H) ->
                    %% Multiple rules (e.g. rate-limit: over→drop, under→accept)
                    [nft_encode:rule_fun(Family, Table, ChainBin, R)
                     || R <- Compiled];
                _ ->
                    [nft_encode:rule_fun(Family, Table, ChainBin, Compiled)]
            end,
            {lists:reverse(NewMsgs) ++ RA, MA}
        catch C:Err ->
            logger:warning("erlkoenig_config: nft rule compile error: ~p:~p for ~p",
                           [C, Err, Rule]),
            {RA, MA}
        end
    end, {[], []}, AllExpanded),

    %% RuleMsgs are accumulated with prepend, so reverse.
    {ChainMsg, MapMsgs, lists:reverse(RuleMsgs)}.

%% ===================================================================
%% Explicit Map/VMap Compilation (from DSL nft_map/nft_vmap blocks)
%% ===================================================================

%% Compile an explicit data map (nft_map) from DSL.
%% Used for jhash loadbalancing: hash result → container IP.
-spec compile_explicit_map(non_neg_integer(), binary(), map(), map()) -> [fun()].
compile_explicit_map(Family, Table, #{name := Name, key_type := KT,
                                       data_type := DT, entries := Entries},
                     ReplicaIpMap) ->
    MapName = iolist_to_binary(Name),
    MapId = erlang:phash2(MapName) band 16#FFFF,
    %% Resolve replica_ips entries
    ResolvedEntries = resolve_map_entries(Entries, ReplicaIpMap, KT, DT),
    CreateMap = fun(S) ->
        nft_set:add_data_map(Family, #{
            table => Table, name => MapName,
            key_type => nft_type_atom_to_int(KT),
            key_len => nft_type_len(KT),
            data_type => DT
        }, MapId, S)
    end,
    AddElems = fun(S) ->
        nft_set_elem:add_data_map_elems(Family, Table, MapName,
            ResolvedEntries, MapId, S)
    end,
    [CreateMap, AddElems].

%% Split [Create, AddElems, Create, AddElems, ...] into two lists.
%% compile_explicit_map/vmap always return [CreateMsg, AddElemsMsg] pairs.
split_create_elems(Funs) ->
    split_create_elems(Funs, [], []).

split_create_elems([], Creates, Elems) ->
    {lists:reverse(Creates), lists:reverse(Elems)};
split_create_elems([Create, AddElems | Rest], Creates, Elems) ->
    split_create_elems(Rest, [Create | Creates], [AddElems | Elems]);
split_create_elems([Single | Rest], Creates, Elems) ->
    %% Safety: single-element case
    split_create_elems(Rest, [Single | Creates], Elems).

%% Compile an explicit verdict map (nft_vmap) from DSL.
-spec compile_explicit_vmap(non_neg_integer(), binary(), map(), map(), map()) -> [fun()].
compile_explicit_vmap(Family, Table, #{name := Name, concat := true,
                                        fields := Fields, entries := Entries},
                      _VethMap, ReplicaIpMap) ->
    VmapName = iolist_to_binary(Name),
    VmapId = erlang:phash2(VmapName) band 16#FFFF,
    FieldAtoms = [binary_to_existing_atom(F, utf8) || F <- Fields,
                  is_binary(F)] ++ [F || F <- Fields, is_atom(F)],
    ResolvedEntries = resolve_vmap_entries(Entries, ReplicaIpMap, FieldAtoms),
    CreateVmap = fun(S) ->
        nft_set:add_concat_vmap(Family, #{
            table => Table, name => VmapName,
            fields => FieldAtoms, id => VmapId
        }, VmapId, S)
    end,
    AddElems = fun(S) ->
        nft_set_elem:add_vmap_elems(Family, Table, VmapName,
            ResolvedEntries, VmapId, S)
    end,
    [CreateVmap, AddElems];
compile_explicit_vmap(Family, Table, #{name := Name, type := Type,
                                        entries := Entries},
                      VethMap, _ReplicaIpMap) ->
    %% Simple (non-concat) vmap — resolve {veth_of, Pod, Ct} keys
    VmapName = iolist_to_binary(Name),
    VmapId = erlang:phash2(VmapName) band 16#FFFF,
    BinEntries = lists:filtermap(fun({K, V}) ->
        case resolve_vmap_key(Type, K, VethMap) of
            {ok, BinKey} -> {true, {BinKey, verdict_atom(V)}};
            skip -> false
        end
    end, Entries),
    CreateVmap = fun(S) ->
        nft_set:add_vmap(Family, #{
            table => Table, name => VmapName, type => Type
        }, VmapId, S)
    end,
    AddElems = fun(S) ->
        nft_set_elem:add_vmap_elems(Family, Table, VmapName,
            BinEntries, VmapId, S)
    end,
    [CreateVmap, AddElems].

%% Resolve map entries — expand {:replica_ips, Pod, Ct} AND
%% normalize static entries to the (binary, binary) pairs the
%% wire-encoder wants.  Previously static entries flowed through
%% as-is — including raw IP tuples — and the kernel silently
%% stored them as zero-length elements (visible: empty map after
%% load).
resolve_map_entries({replica_ips, Pod, Ct}, ReplicaIpMap, _KT, _DT) ->
    PodBin = iolist_to_binary(Pod),
    CtBin  = iolist_to_binary(Ct),
    case maps:get({PodBin, CtBin}, ReplicaIpMap, []) of
        [] ->
            %% Same Glasbox class as `dnat_lb' and the generic
            %% expand_nft_rule replica_ips path — silent empty map
            %% would leave a downstream DNAT rule looking up an
            %% empty set, silently dropping traffic that was supposed
            %% to load-balance to backend replicas. Fail loud so the
            %% operator sees the unresolvable reference at apply time.
            error({map_replica_ips_no_targets,
                   #{pod => PodBin, container => CtBin,
                     hint => <<"map `entries: {:replica_ips, Pod, Ct}' "
                               "references a pod/container with 0 spawned "
                               "replicas at apply time — fix pod name or "
                               "order dependencies so the target pod "
                               "spawns first">>}});
        IpList ->
            lists:zip(
                [<<Idx:32/big>> || Idx <- lists:seq(0, length(IpList) - 1)],
                [ip_to_binary(Ip) || Ip <- IpList]
            )
    end;
resolve_map_entries(Entries, _ReplicaIpMap, KT, DT) when is_list(Entries) ->
    [{normalize_map_key(K, KT), normalize_map_key(V, DT)}
     || {K, V} <- Entries].

%% Normalize a map key/value to the 4/2/N-byte binary the kernel
%% expects for the named type.  Fail-loud on bad shape so operators
%% don't discover empty maps at runtime.
normalize_map_key(<<B/binary>>, _Type) -> B;
normalize_map_key({A, B, C, D}, ipv4_addr) -> <<A, B, C, D>>;
normalize_map_key({A, B, C, D, _Prefix}, ipv4_addr) -> <<A, B, C, D>>;
normalize_map_key(Port, inet_service) when is_integer(Port),
                                            Port >= 0, Port =< 65535 ->
    <<Port:16/big>>;
normalize_map_key(Other, Type) ->
    error({bad_map_entry_value, #{value => Other, expected_type => Type}}).

%% Resolve vmap entries — convert tuples to binary keys
resolve_vmap_entries(Entries, _ReplicaIpMap, _Fields) when is_list(Entries) ->
    lists:map(fun(Entry) when is_tuple(Entry) ->
        L = tuple_to_list(Entry),
        Verdict = lists:last(L),
        KeyParts = lists:droplast(L),
        Key = iolist_to_binary([vmap_field_to_bin(P) || P <- KeyParts]),
        {Key, verdict_atom(Verdict)}
    end, Entries).

vmap_field_to_bin({A, B, C, D}) -> <<A, B, C, D>>;
vmap_field_to_bin(Port) when is_integer(Port) -> <<Port:16/big, 0:16>>;
vmap_field_to_bin(Bin) when is_binary(Bin) -> Bin.

verdict_atom(accept) -> accept;
verdict_atom(drop) -> drop;
verdict_atom({jump, Chain}) -> {jump, iolist_to_binary(Chain)};
verdict_atom({goto, Chain}) -> {goto, iolist_to_binary(Chain)}.

vmap_key(ipv4_addr, {A, B, C, D}) -> <<A, B, C, D>>;
vmap_key(inet_service, Port) -> <<Port:16/big>>;
vmap_key(mark, Val) -> <<Val:32/big>>;
vmap_key(ifname, Name) ->
    Bin = iolist_to_binary(Name),
    Pad = 16 - byte_size(Bin),
    <<Bin/binary, 0:(Pad*8)>>;
vmap_key(_, Val) when is_binary(Val) -> Val.

%% Resolve a vmap key — expand {veth_of, Pod, Ct} via VethMap
resolve_vmap_key(Type, {veth_of, Pod, Ct}, VethMap) ->
    PodBin = iolist_to_binary(Pod),
    CtBin = iolist_to_binary(Ct),
    case maps:find({PodBin, CtBin}, VethMap) of
        {ok, Veth} -> {ok, vmap_key(Type, Veth)};
        error ->
            logger:warning("erlkoenig_config: veth_of ~s.~s not found for vmap",
                           [Pod, Ct]),
            skip
    end;
resolve_vmap_key(Type, Key, _VethMap) ->
    {ok, vmap_key(Type, Key)}.

nft_type_atom_to_int(mark) -> 19;
nft_type_atom_to_int(ipv4_addr) -> 7;
nft_type_atom_to_int(inet_service) -> 13;
nft_type_atom_to_int(_) -> 0.

nft_type_len(mark) -> 4;
nft_type_len(ipv4_addr) -> 4;
nft_type_len(inet_service) -> 2;
nft_type_len(_) -> 4.

%% =================================================================
%% Rule expansion
%% =================================================================

%% Expand a single nft rule, resolving {:veth_of,...} and {:replica_ips,...}.
%% Returns a list of rules (one per replica IP when expanded).
-spec expand_nft_rule(atom(), map(), map(), map()) -> [term()].

expand_nft_rule(jump, #{to := Target} = Opts, VethMap, ReplicaIpMap) ->
    TargetBin = iolist_to_binary(Target),
    %% Previously this clause dropped every option except `to' and
    %% `iifname' — so a rule like `jump to: threat_chain, tcp_dport: 80,
    %% counter: jumped' turned into an UNCONDITIONAL jump with no
    %% counter. That silently widened the declared match (Glasbox
    %% violation — security rule implementations diverged from what
    %% the operator wrote).
    %%
    %% Fix: delegate the per-key translation to the generic clause
    %% below (accept is just a placeholder verdict — we overwrite it),
    %% then graft the resolved chain name on top. The generic path
    %% already handles iifname {:veth_of, _, _} → iif, tcp_dport → tcp,
    %% counter → binary, saddr prefix, etc.
    RestOpts = maps:remove(to, Opts),
    [{rule, _, Expanded}] =
        expand_nft_rule(accept, RestOpts, VethMap, ReplicaIpMap),
    [{rule, jump, Expanded#{chain => TargetBin}}];

%% vmap_lookup: explicit verdict map lookup (concat or simple)
expand_nft_rule(vmap_lookup, #{vmap := VmapName} = Opts, _VethMap, _ReplicaIpMap) ->
    Base = #{vmap => VmapName},
    Base2 = case maps:find(fields, Opts) of
        {ok, Fields} -> Base#{fields => Fields};
        error -> Base
    end,
    Base3 = case maps:find(type, Opts) of
        {ok, Type} -> Base2#{type => Type};
        error -> Base2
    end,
    [{rule, vmap_lookup, Base3}];

%% dnat_jhash: explicit map reference, no implicit map creation
expand_nft_rule(flow_offload, #{flowtable := FtName}, _VethMap, _ReplicaIpMap) ->
    [{flow_offload, iolist_to_binary(FtName)}];

expand_nft_rule(dnat_jhash, Opts, VethMap, _ReplicaIpMap) ->
    MapName = maps:get(map, Opts),
    %% Accept either `port:' (internal shorthand) or `dport:' (DSL
    %% tutorial form). `tcp_dport:' is the explicit tcp-specific
    %% variant — normalised via the clause below.
    Port = case maps:get(dport, Opts, undefined) of
        undefined -> maps:get(port, Opts, 0);
        P         -> P
    end,
    Mod = maps:get(mod, Opts),
    BaseOpts = maps:fold(fun
        (iifname, {veth_of, P, C}, Acc) ->
            case maps:find({P, C}, VethMap) of
                {ok, Veth} ->
                    Acc#{iif => Veth};
                error ->
                    %% Match the generic-clause behavior: emit
                    %% `__unresolved__' as a fail-CLOSED placeholder.
                    %% Silent `Acc' (no iif key) would DROP the
                    %% interface constraint entirely and let the
                    %% dnat_jhash rule fire on ANY inbound interface
                    %% — the declared boundary was "traffic from
                    %% pod.ct's veth", the actual boundary became
                    %% "any traffic matching the port". Fail-open
                    %% Glasbox violation. `__unresolved__' never
                    %% matches a real interface so the rule is dead
                    %% until the reference can be resolved.
                    logger:warning(
                        "erlkoenig_config: dnat_jhash veth_of ~s.~s "
                        "unresolved — rule pinned to __unresolved__ "
                        "until target pod spawns",
                        [P, C]),
                    Acc#{iif => <<"__unresolved__">>}
            end;
        (iifname, V, Acc) -> Acc#{iif => iolist_to_binary(V)};
        (tcp_dport, P, Acc) -> Acc#{tcp => P};
        (counter, N, Acc) -> Acc#{counter => iolist_to_binary(N)};
        (map, _, Acc) -> Acc;
        (port, _, Acc) -> Acc;
        (dport, _, Acc) -> Acc;
        (mod, _, Acc) -> Acc;
        (K, V, _Acc) ->
            error({unknown_nft_rule_opt,
                   #{context => dnat_jhash, key => K, value => V,
                     hint => <<"unknown option in dnat_jhash rule — "
                               "supported: iifname, tcp_dport, counter, "
                               "map, port, dport, mod">>}})
    end, #{}, Opts),
    [{rule, dnat_jhash, BaseOpts#{map => MapName, dport => Port, mod => Mod}}];

%% dnat_lb: legacy — collect ALL replica IPs into one rule (not expanded to N rules)
expand_nft_rule(dnat_lb, Opts, VethMap, ReplicaIpMap) ->
    Port = maps:get(port, Opts, 0),
    Targets = case maps:get(targets, Opts, undefined) of
        {replica_ips, Pod, Ct} ->
            IpList = maps:get({Pod, Ct}, ReplicaIpMap, []),
            case IpList of
                [] ->
                    %% Fail loud: empty LB target list means either the
                    %% referenced pod doesn't exist, or none of its
                    %% replicas have spawned yet.  Silently emitting a
                    %% DNAT rule with no backends is a Glasbox
                    %% violation — the rule would match traffic and
                    %% DNAT it into nowhere (kernel returns undefined
                    %% behaviour).
                    error({dnat_lb_no_targets,
                           #{pod => Pod, container => Ct,
                             hint => <<"dnat_lb targets pod/container "
                                       "has 0 spawned replicas at apply-"
                                       "time — check pod/container name "
                                       "or order dependencies so the "
                                       "target pod spawns first">>}});
                _ ->
                    [ip_to_binary(Ip) || Ip <- IpList]
            end;
        undefined ->
            error({dnat_lb_missing_targets,
                   #{hint => <<"dnat_lb rule requires `targets:' with "
                               "a {:replica_ips, Pod, Ct} reference">>}});
        Other ->
            error({dnat_lb_bad_targets, #{value => Other}})
    end,
    BaseOpts = maps:fold(fun
        (iifname, {veth_of, P, C}, Acc) ->
            case maps:find({P, C}, VethMap) of
                {ok, Veth} ->
                    Acc#{iif => Veth};
                error ->
                    %% See dnat_jhash above — fail-closed via
                    %% `__unresolved__' placeholder. Silent-skip
                    %% would widen dnat_lb to match ANY inbound
                    %% interface (security regression vs. declared
                    %% pod.ct-scoped traffic).
                    logger:warning(
                        "erlkoenig_config: dnat_lb veth_of ~s.~s "
                        "unresolved — rule pinned to __unresolved__ "
                        "until target pod spawns",
                        [P, C]),
                    Acc#{iif => <<"__unresolved__">>}
            end;
        (iifname, V, Acc) -> Acc#{iif => iolist_to_binary(V)};
        (tcp_dport, P, Acc) -> Acc#{tcp => P};
        (counter, N, Acc) -> Acc#{counter => iolist_to_binary(N)};
        (targets, _, Acc) -> Acc;
        (port, _, Acc) -> Acc;
        (K, V, _Acc) ->
            error({unknown_nft_rule_opt,
                   #{context => dnat_lb, key => K, value => V,
                     hint => <<"unknown option in dnat_lb rule — "
                               "supported: iifname, tcp_dport, counter, "
                               "targets, port">>}})
    end, #{}, Opts),
    [{rule, dnat_lb, BaseOpts#{targets => Targets, dport => Port}}];

expand_nft_rule(Action, Opts, VethMap, ReplicaIpMap) ->
    %% Resolve all {:veth_of,...} and {:replica_ips,...} in opts.
    %%
    %% Muster-9 hazard: the generic `(Key, V, Acc) -> iolist_to_binary(V)'
    %% clauses for oifname/oifname_ne would happily gobble a
    %% `{veth_of, Pod, Ct}' tuple and crash in iolist_to_binary/1 with
    %% a cryptic badarg. Specific tuple clauses therefore come FIRST,
    %% mirroring the iifname handler one line below. See also
    %% finding_nft_container_veth_of_unreachable.md for the same
    %% pattern caught in translate_opts/1.
    Resolved = maps:fold(fun
        (iifname, {veth_of, Pod, Ct}, Acc) ->
            case maps:find({Pod, Ct}, VethMap) of
                {ok, Veth} -> Acc#{iif => Veth};
                error -> Acc#{iif => <<"__unresolved__">>}
            end;
        (oifname, {veth_of, Pod, Ct}, Acc) ->
            case maps:find({Pod, Ct}, VethMap) of
                {ok, Veth} -> Acc#{oif => Veth};
                error -> Acc#{oif => <<"__unresolved__">>}
            end;
        (oifname_ne, {veth_of, Pod, Ct}, Acc) ->
            case maps:find({Pod, Ct}, VethMap) of
                {ok, Veth} -> Acc#{oif_neq => Veth};
                error -> Acc#{oif_neq => <<"__unresolved__">>}
            end;
        (iifname, V, Acc) -> Acc#{iif => iolist_to_binary(V)};
        (oifname, V, Acc) -> Acc#{oif => iolist_to_binary(V)};
        (oifname_ne, V, Acc) -> Acc#{oif_neq => iolist_to_binary(V)};
        (ip_saddr, {replica_ips, Pod, Ct}, Acc) ->
            Acc#{saddr => {replica_ips, Pod, Ct}};
        (ip_daddr, {replica_ips, Pod, Ct}, Acc) ->
            Acc#{daddr => {replica_ips, Pod, Ct}};
        (ip_saddr, {A,B,C,D,Prefix}, Acc) ->
            Acc#{saddr => {A,B,C,D,Prefix}};
        (ip_saddr, {A,B,C,D}, Acc) ->
            Acc#{saddr => {A,B,C,D,32}};
        (ip_daddr, {A,B,C,D,Prefix}, Acc) ->
            Acc#{daddr => {A,B,C,D,Prefix}};
        (ip_daddr, {A,B,C,D}, Acc) ->
            Acc#{daddr => {A,B,C,D,32}};
        (ip_protocol, Proto, Acc) -> Acc#{protocol => Proto};
        (tcp_dport, Port, Acc) -> Acc#{tcp => Port};
        (udp_dport, Port, Acc) -> Acc#{udp => Port};
        (ct_state, States, Acc) when is_list(States), States =/= [] ->
            %% Mirror of erlkoenig_nft_container:translate_opts/1: the
            %% downstream `compile_generic_rule' only recognises
            %% `ct => established' (which maps to ct_established_accept/0,
            %% a mask that matches established OR related). Any OTHER
            %% atom — `new', `invalid', or a list like `[:new, :established]' —
            %% used to pass `hd(States)' through and was then silently
            %% dropped by compile_generic_rule, producing a rule with
            %% NO ct filter. That's wider than the declared intent and
            %% a Glasbox violation.  Fail loud for unsupported forms.
            case lists:all(fun(S) ->
                                S =:= established orelse S =:= related
                           end, States) of
                true ->
                    Acc#{ct => established};
                false ->
                    error({unsupported_ct_state,
                           #{states => States,
                             supported => [established, related],
                             hint => <<"host nft_table ct_state currently "
                                       "only supports [:established] and/or "
                                       "[:related]. New/invalid matches "
                                       "would widen the rule silently.">>}})
            end;
        (ct_state, States, _Acc) ->
            error({invalid_ct_state,
                   #{states => States,
                     hint => <<"ct_state must be a non-empty list">>}});
        (log_prefix, Prefix, Acc) -> Acc#{log => Prefix};
        (log, Prefix, Acc) -> Acc#{log => Prefix};
        (counter, Name, Acc) -> Acc#{counter => iolist_to_binary(Name)};
        %% Named-object references (set/map/vmap/flowtable) pass
        %% through with the operator-given name.  The downstream
        %% compile step resolves them to SET_IDs at batch-emit.
        (set, Name, Acc) -> Acc#{set => iolist_to_binary(Name)};
        (vmap, Name, Acc) -> Acc#{vmap => iolist_to_binary(Name)};
        (flowtable, Name, Acc) -> Acc#{flowtable => iolist_to_binary(Name)};
        %% jhash-related options for dnat_jhash verdict (see dnat_jhash
        %% clause above for the primary handler; generic expand also
        %% sees them when the verdict is dnat_jhash reached here).
        (map, Name, Acc) -> Acc#{map => iolist_to_binary(Name)};
        (dport, Port, Acc) -> Acc#{dport => Port};
        (mod, N, Acc) -> Acc#{mod => N};
        %% Rate-limit modifier (consumed by compile_generic_modifiers).
        %% Accepts both map form `%{rate: R, burst: B}' and legacy
        %% tuple form `{R, [burst: B]}' — the firewall compiler
        %% normalizes both.
        (limit, L, Acc) -> Acc#{limit => L};
        %% connlimit_drop carries `max' as a rule-level opt
        (max, N, Acc) when is_integer(N) -> Acc#{max => N};
        (over, N, Acc) when is_integer(N) -> Acc#{over => N};
        (K, V, _Acc) ->
            error({unknown_nft_rule_opt,
                   #{context => generic_rule, verdict => Action,
                     key => K, value => V,
                     hint => <<"unknown nft rule option — check spelling "
                               "(e.g. ip_saddr vs ip_saddrr). See "
                               "SPEC-EK-023 §3 for supported keys.">>}})
    end, #{}, Opts),

    %% Expand replica_ips into multiple rules (cartesian product).
    %%
    %% Previously, a `{replica_ips, Pod, Ct}' reference with zero
    %% matching replicas produced an empty expansion list. The
    %% cartesian-product list comprehension below then produced ZERO
    %% rules — the operator's declared rule SILENTLY VANISHED. If it
    %% was an `accept' rule, the default-drop policy blocked the
    %% intended traffic. If it was a `drop' rule, traffic that should
    %% have been blocked went through. In either direction, a
    %% Glasbox-violating silent boundary shift.
    %%
    %% `dnat_lb' already fails loud on the same condition (L1332).
    %% The generic path now matches — operator sees a clear error
    %% naming the unresolvable reference instead of debugging a rule
    %% that "didn't apply for some reason".
    %% replica_ips that resolve to [] at apply time can happen
    %% legitimately during bring-up: the referenced pod's replicas
    %% haven't spawned yet (parallel pod startup). Emit a fail-closed
    %% `__unresolved__' placeholder and log, same shape as the
    %% dnat_jhash / dnat_lb path (bug #75). Downstream nft_table:apply
    %% filters out rules with any `__unresolved__' field, so the
    %% rule is no-op'd cleanly rather than crashing the whole batch
    %% and blocking every pod in the deployment.
    SaddrExpand = case maps:find(saddr, Resolved) of
        {ok, {replica_ips, SP, SC}} ->
            case maps:get({SP, SC}, ReplicaIpMap, []) of
                [] ->
                    logger:warning(
                        "nft_compile: saddr replica_ips(~p, ~p) "
                        "resolved to 0 IPs at apply time — rule "
                        "pinned to __unresolved__ until next "
                        "reconcile",
                        [SP, SC]),
                    [<<"__unresolved__">>];
                SIps -> SIps
            end;
        {ok, Ip} -> [Ip];
        error -> [undefined]
    end,
    DaddrExpand = case maps:find(daddr, Resolved) of
        {ok, {replica_ips, DP, DC}} ->
            case maps:get({DP, DC}, ReplicaIpMap, []) of
                [] ->
                    logger:warning(
                        "nft_compile: daddr replica_ips(~p, ~p) "
                        "resolved to 0 IPs at apply time — rule "
                        "pinned to __unresolved__ until next "
                        "reconcile",
                        [DP, DC]),
                    [<<"__unresolved__">>];
                DIps -> DIps
            end;
        {ok, Ip2} -> [Ip2];
        error -> [undefined]
    end,

    BaseOpts = maps:without([saddr, daddr], Resolved),

    [{rule, Action, build_rule_opts(BaseOpts, S, D)}
     || S <- SaddrExpand, D <- DaddrExpand].

build_rule_opts(Base, undefined, undefined) -> Base;
build_rule_opts(Base, Saddr, undefined) ->
    Base#{saddr => ip_to_cidr(Saddr)};
build_rule_opts(Base, undefined, Daddr) ->
    Base#{daddr => ip_to_cidr(Daddr)};
build_rule_opts(Base, Saddr, Daddr) ->
    Base#{saddr => ip_to_cidr(Saddr), daddr => ip_to_cidr(Daddr)}.

ip_to_cidr({A,B,C,D}) -> {A,B,C,D,32};
ip_to_cidr({A,B,C,D,P}) -> {A,B,C,D,P};
ip_to_cidr(Other) -> Other.

ip_to_binary({A,B,C,D}) -> <<A,B,C,D>>;
ip_to_binary({A,B,C,D,_Prefix}) -> <<A,B,C,D>>;
ip_to_binary(B) when is_binary(B) -> B.

priority_to_int(filter) -> 0;
priority_to_int(dstnat) -> -100;
priority_to_int(srcnat) -> 100;
priority_to_int(mangle) -> -150;
priority_to_int(security) -> 50;
priority_to_int(raw) -> -300;
priority_to_int(N) when is_integer(N) -> N.

%% =================================================================
%% Zone chains
%% =================================================================

%% Apply zone-level chains as nft rules in the erlkoenig_ct forward chain.
%% Zone chains contain explicit rule terms ({rule, Verdict, Opts}) that get
%% compiled via erlkoenig_ct_firewall:compile_generic_rule and added to
%% the forward chain.
-spec apply_zone_chains(map(), map()) -> ok.
apply_zone_chains(#{chains := Chains} = Zone, IpMap) ->
    ZoneName = maps:get(name, Zone, <<"?">>),
    BridgeName = iolist_to_binary(maps:get(bridge, Zone,
        <<"ek_br_", (iolist_to_binary(ZoneName))/binary>>)),
    Ctx = #{bridge => BridgeName, ip_map => IpMap},
    lists:foreach(fun(#{rules := Rules} = Chain) ->
        ChainTarget = case maps:get(hook, Chain, nil) of
            nil -> <<"forward">>;
            input -> <<"input">>;
            forward -> <<"forward">>;
            postrouting -> <<"postrouting">>;
            prerouting -> <<"prerouting">>;
            output -> <<"output">>
        end,
        %% Named counter + NFLOG for zone forward drops (SPEC-EK-005)
        DropCounterName = <<"zone_", (iolist_to_binary(ZoneName))/binary, "_drop">>,
        NflogGroup = erlkoenig_ct_firewall:next_nflog_group(),
        DropCounterMsg = [fun(S) ->
            nft_object:add_counter(1, <<"erlkoenig">>, DropCounterName, S)
        end],
        RuleMsgs = lists:flatmap(fun(Rule) ->
            Resolved = resolve_host_refs(Rule, Ctx),
            lists:filtermap(fun(R) ->
                try
                    Compiled = erlkoenig_ct_firewall:compile_rule(R),
                    %% Inject counter + nflog on drop rules
                    Compiled2 = erlkoenig_ct_firewall:inject_drop_observability(
                        [Compiled], DropCounterName, NflogGroup),
                    {true, nft_encode:rule_fun(inet, <<"erlkoenig">>,
                        ChainTarget, hd(Compiled2))}
                catch _:Err ->
                    logger:warning("erlkoenig_config: zone ~s rule compile error: ~p for ~p",
                                   [ZoneName, Err, R]),
                    false
                end
            end, Resolved)
        end, Rules),
        case RuleMsgs of
            [] -> ok;
            _ ->
                %% Start NFLOG receiver for this zone's drops
                _ = case erlkoenig_nft_nflog:start_link(NflogGroup) of
                    {ok, _} ->
                        logger:info("erlkoenig_config: nflog group ~p for zone ~s",
                                    [NflogGroup, ZoneName]);
                    {error, NflogErr} ->
                        logger:warning("erlkoenig_config: nflog failed for zone ~s: ~p",
                                        [ZoneName, NflogErr])
                end,
                case nfnl_server:apply_msgs(erlkoenig_nft_srv, DropCounterMsg ++ RuleMsgs) of
                    ok ->
                        logger:info("erlkoenig_config: zone ~s: ~p forward rules applied",
                                    [ZoneName, length(RuleMsgs)]);
                    {error, Reason} ->
                        logger:warning("erlkoenig_config: zone ~s chain apply failed: ~p",
                                       [ZoneName, Reason])
                end
        end
    end, Chains).

%% Resolve symbolic references in rules:
%%   :bridge      → zone bridge name (e.g. "ek_br_test")
%%   :containers  → "vh_*" (all container veths)
%%   "pod.ct"     → IP-based match (saddr/daddr) for pod-qualified names
%%
%% Returns a list of rules. Pod-qualified names with multiple replicas
%% expand to one rule per replica (e.g. "worker.fn" with 5 replicas
%% produces 5 rules, each matching a different replica IP).
-spec resolve_host_refs(term(), map()) -> [term()].
resolve_host_refs({rule, Verdict, Opts}, Ctx) when is_map(Opts) ->
    IpMap = maps:get(ip_map, Ctx, #{}),
    %% First pass: resolve non-pod refs, collect pod refs separately
    {BaseOpts, PodRefs} = maps:fold(fun
        (iif, bridge, {Acc, Refs}) ->
            {Acc#{iif => maps:get(bridge, Ctx, <<"br0">>)}, Refs};
        (oif, bridge, {Acc, Refs}) ->
            {Acc#{oif => maps:get(bridge, Ctx, <<"br0">>)}, Refs};
        (oif, containers, {Acc, Refs}) ->
            {Acc#{oif => <<"vh_*">>}, Refs};
        (Dir, Name, {Acc, Refs}) when (Dir =:= iif orelse Dir =:= oif) andalso is_binary(Name) ->
            case binary:split(Name, <<".">>) of
                [PodName, CtName] ->
                    %% Pod-qualified: collect all replica IPs
                    Ips = find_all_replica_ips(PodName, CtName, IpMap),
                    IpKey = case Dir of iif -> saddr; oif -> daddr end,
                    case Ips of
                        [] -> {Acc#{Dir => Name}, Refs};
                        _ -> {Acc, [{IpKey, Ips} | Refs]}
                    end;
                _ ->
                    {Acc#{Dir => Name}, Refs}
            end;
        (K, V, {Acc, Refs}) -> {Acc#{K => V}, Refs}
    end, {#{}, []}, Opts),
    %% Second pass: expand pod refs into multiple rules via cartesian product
    case PodRefs of
        [] ->
            [{rule, Verdict, BaseOpts}];
        _ ->
            expand_pod_ref_rules(Verdict, BaseOpts, PodRefs)
    end;
resolve_host_refs(Rule, _Ctx) ->
    [Rule].

%% Find all IPs for a pod-qualified name across all replicas.
%% "worker" + "fn" matches "worker-0-fn", "worker-1-fn", etc.
-spec find_all_replica_ips(binary(), binary(), map()) -> [tuple()].
find_all_replica_ips(PodName, CtName, IpMap) ->
    Prefix = <<PodName/binary, "-">>,
    Suffix = <<"-", CtName/binary>>,
    PrefixLen = byte_size(Prefix),
    SuffixLen = byte_size(Suffix),
    maps:fold(fun(Name, Ip, Acc) ->
        NameLen = byte_size(Name),
        case NameLen > PrefixLen + SuffixLen of
            true ->
                case {binary:part(Name, 0, PrefixLen),
                      binary:part(Name, NameLen - SuffixLen, SuffixLen)} of
                    {Prefix, Suffix} -> [Ip | Acc];
                    _ -> Acc
                end;
            false ->
                case Name =:= <<PodName/binary, "-0-", CtName/binary>> of
                    true -> [Ip | Acc];
                    false -> Acc
                end
        end
    end, [], IpMap).

%% Expand pod refs into one rule per IP combination.
%% For a single pod ref (common case): one rule per IP.
%% For two pod refs (e.g. iif+oif both pod-qualified): cartesian product.
-spec expand_pod_ref_rules(atom(), map(), [{atom(), [tuple()]}]) -> [term()].
expand_pod_ref_rules(Verdict, BaseOpts, [{IpKey, Ips}]) ->
    [{rule, Verdict, BaseOpts#{IpKey => {element(1,Ip), element(2,Ip),
                                         element(3,Ip), element(4,Ip), 32}}}
     || Ip <- Ips];
expand_pod_ref_rules(Verdict, BaseOpts, [{K1, Ips1}, {K2, Ips2}]) ->
    [{rule, Verdict, BaseOpts#{K1 => {element(1,I1), element(2,I1),
                                      element(3,I1), element(4,I1), 32},
                                K2 => {element(1,I2), element(2,I2),
                                      element(3,I2), element(4,I2), 32}}}
     || I1 <- Ips1, I2 <- Ips2];
expand_pod_ref_rules(_Verdict, BaseOpts, _) ->
    %% Fallback: more than 2 pod refs is unusual, just emit base
    [{rule, _Verdict, BaseOpts}].

%% =================================================================
%% Pod forward chains
%% =================================================================

%% Apply pod-internal forward chains after containers are spawned.
%% Resolves @ref (container name → veth) and adds rules to nft.
%% Returns [{PodChainName, [Veth, ...]}] for forward chain rebuild.
-spec apply_pod_forward_chains([map()], [map()], [{binary(), pid()}]) ->
    [{binary(), [binary()]}].
apply_pod_forward_chains(Pods, Zones, SpawnedPids) ->
    %% Build Name → veth map from spawned pids via inspect
    RunningMap = lists:foldl(fun({Name, Pid}, Acc) ->
        try erlkoenig:inspect(Pid) of
            #{net_info := #{host_veth := Veth, ip := Ip}} ->
                logger:info("erlkoenig_config: pod veth map: ~s → ~s ~p",
                            [Name, Veth, Ip]),
                Acc#{Name => #{host_veth => Veth, ip => Ip}};
            Other when is_map(Other) ->
                logger:warning("erlkoenig_config: inspect ~s: no net_info: ~p",
                               [Name, maps:keys(Other)]),
                Acc;
            Other ->
                logger:warning("erlkoenig_config: inspect ~s: unexpected: ~p",
                               [Name, Other]),
                Acc
        catch C:E ->
            logger:warning("erlkoenig_config: inspect ~s failed: ~p:~p", [Name, C, E]),
            Acc
        end
    end, #{}, SpawnedPids),

    lists:flatmap(fun(Pod) ->
        PodName = iolist_to_binary(maps:get(name, Pod, <<"?">>)),
        PodChains = maps:get(chains, Pod, []),
        case PodChains of
            [] -> [];
            _ ->
                %% Legacy format: replicas attached to zone deployments.
                ReplicaCounts = lists:filtermap(fun(Zone) ->
                    Deps = maps:get(deployments, Zone, []),
                    case lists:search(fun(#{pod := P}) ->
                        iolist_to_binary(P) =:= PodName
                    end, Deps) of
                        {value, #{replicas := N}} -> {true, N};
                        _ -> false
                    end
                end, Zones),
                ZoneReplicas = lists:sum(ReplicaCounts),
                PodContainers = maps:get(containers, Pod, []),
                ContainerNames = [iolist_to_binary(maps:get(name, C, <<"?">>))
                                  || C <- PodContainers],
                %% New format: replicas declared inline on each container.
                %% Use the max across containers as the pod instance
                %% count — a pod with frontend:3+backend:1 still gets
                %% 3 rule-instances, and container-level missing veths
                %% land in the existing RefMap warning path. Without
                %% this fallback, any pod declared in the new DSL style
                %% without matching zone deployments would silently emit
                %% 0 pod chains (lists:seq(0, -1) = []).
                InlineReplicas = lists:max(
                    [1 | [maps:get(replicas, C, 1) || C <- PodContainers]]),
                Replicas = case ZoneReplicas of
                    0 -> InlineReplicas;
                    _ -> ZoneReplicas
                end,
                apply_pod_chains_for_replicas(PodName, PodChains, ContainerNames,
                                              Replicas, RunningMap)
        end
    end, Pods).

-spec apply_pod_chains_for_replicas(binary(), [map()], [binary()],
                                     non_neg_integer(), map()) ->
    [{binary(), [binary()]}].
apply_pod_chains_for_replicas(PodName, PodChains, ContainerNames, Replicas, RunningMap) ->
    lists:filtermap(fun(ReplicaIdx) ->
        %% Build ref map for this replica: "frontend" → "vh_abc123"
        IdxBin = integer_to_binary(ReplicaIdx),
        RefMap = lists:foldl(fun(CtName, Acc) ->
            FullName = <<PodName/binary, "-", IdxBin/binary, "-", CtName/binary>>,
            case maps:find(FullName, RunningMap) of
                {ok, Info} when is_map(Info) ->
                    Acc#{CtName => Info};
                _ ->
                    logger:warning("erlkoenig_config: pod ~s ref ~s not found in running containers",
                                   [PodName, FullName]),
                    Acc
            end
        end, #{}, ContainerNames),

        %% Create a dedicated regular chain for this pod instance's forward rules.
        %% Then add a jump from the main forward chain BEFORE the per-container
        %% jump rules (which would otherwise intercept the traffic).
        PodChainName = iolist_to_binary([<<"pod_">>, PodName, <<"_">>, IdxBin]),

        HasChains = lists:any(fun(#{rules := R}) -> R =/= []; (_) -> false end, PodChains),
        %% Resolve @ref to IP and add rules directly to forward chain.
        %% Bridge traffic uses saddr/daddr because br_netfilter shows
        %% the bridge as iifname/oifname, not the container veths.
        _ = HasChains,
        _ = PodChainName,
        lists:foreach(fun(#{rules := Rules} = _Chain) ->
            ResolvedRules = lists:filtermap(fun(Rule) ->
                resolve_and_compile_rule(Rule, RefMap, PodName, <<"forward">>)
            end, Rules),
            case ResolvedRules of
                [] -> ok;
                _ ->
                    case nfnl_server:apply_msgs(erlkoenig_nft_srv, ResolvedRules) of
                        ok ->
                            logger:info("erlkoenig_config: pod ~s-~p: ~p forward rules",
                                        [PodName, ReplicaIdx, length(ResolvedRules)]);
                        {error, Reason} ->
                            logger:warning("erlkoenig_config: pod ~s-~p forward failed: ~p",
                                           [PodName, ReplicaIdx, Reason])
                    end
            end
        end, PodChains),
        false
    end, lists:seq(0, Replicas - 1)).

%% Resolve {ref, Name} in a rule's iif/oif to concrete veth names,
%% then compile to nft expression list targeting the pod chain.
-spec resolve_and_compile_rule(term(), map(), binary(), binary()) ->
    {true, fun()} | false.
resolve_and_compile_rule({rule, Verdict, Opts}, RefMap, PodName, ChainName) when is_map(Opts) ->
    Resolved = maps:fold(fun
        (iif, {ref, Name}, Acc) ->
            case resolve_ref_ip(Name, RefMap, PodName) of
                {ok, Ip} -> Acc#{saddr => {element(1,Ip), element(2,Ip), element(3,Ip), element(4,Ip), 32}};
                error -> Acc#{iif => <<"__unresolved__">>}
            end;
        (oif, {ref, Name}, Acc) ->
            case resolve_ref_ip(Name, RefMap, PodName) of
                {ok, Ip} -> Acc#{daddr => {element(1,Ip), element(2,Ip), element(3,Ip), element(4,Ip), 32}};
                error -> Acc#{oif => <<"__unresolved__">>}
            end;
        %% This branch handles ALREADY-translated internal keys (saddr,
        %% daddr, tcp, udp, ct, protocol, counter, log) coming from
        %% upstream translators — NOT raw DSL keys.  We still warn on
        %% genuinely unknown keys so typos don't just flow silently
        %% through to compile_generic_rule.
        (K, V, Acc) when K =:= saddr; K =:= daddr; K =:= tcp;
                          K =:= udp; K =:= ct; K =:= protocol;
                          K =:= counter; K =:= log;
                          K =:= iif; K =:= oif; K =:= oif_neq ->
            Acc#{K => V};
        (K, V, Acc) ->
            logger:warning("erlkoenig_config: pod-local rule in "
                           "pod ~s has unknown key ~p=~p "
                           "(passing through to compile_generic_rule — "
                           "this path is legacy, prefer host nft_table)",
                           [PodName, K, V]),
            Acc#{K => V}
    end, #{}, Opts),
    case has_unresolved(Resolved) of
        true ->
            logger:warning("erlkoenig_config: pod ~s: unresolved ref in ~p",
                           [PodName, Opts]),
            false;
        false ->
            try
                Compiled = erlkoenig_ct_firewall:compile_generic_rule(Verdict, Resolved),
                {true, nft_encode:rule_fun(inet, <<"erlkoenig">>,
                    ChainName, Compiled)}
            catch _:Err ->
                logger:warning("erlkoenig_config: pod ~s rule compile error: ~p",
                               [PodName, Err]),
                false
            end
    end;
resolve_and_compile_rule(Rule, _RefMap, PodName, ChainName) ->
    try
        Compiled = erlkoenig_ct_firewall:compile_rule(Rule),
        {true, nft_encode:rule_fun(inet, <<"erlkoenig">>,
            ChainName, Compiled)}
    catch _:Err ->
        logger:warning("erlkoenig_config: pod ~s rule compile error: ~p for ~p",
                       [PodName, Err, Rule]),
        false
    end.

-spec resolve_ref_ip(binary(), map(), binary()) -> {ok, tuple()} | error.
resolve_ref_ip(Name, RefMap, PodName) ->
    NameBin = iolist_to_binary(Name),
    case maps:find(NameBin, RefMap) of
        {ok, #{ip := Ip}} -> {ok, Ip};
        _ ->
            logger:warning("erlkoenig_config: pod ~s: @~s not found", [PodName, NameBin]),
            error
    end.

-spec has_unresolved(map()) -> boolean().
has_unresolved(Opts) ->
    lists:any(fun
        ({_, {ref, _}}) -> true;
        ({_, <<"__unresolved__">>}) -> true;
        (_) -> false
    end, maps:to_list(Opts)).

%% An expanded rule from `expand_nft_rule/4' is either the generic
%% `{rule, Verdict, Opts}' tuple produced by the generic path or one
%% of the per-action tagged tuples (`{dnat_jhash, Opts}',
%% `{dnat_lb, Opts}', `{vmap_lookup, Opts}', …) emitted by the
%% specialised branches. Only the generic tuple carries resolvable
%% saddr/daddr as a map; the others embed veth/oif strings inline
%% and have their own `__unresolved__' handling. Checking `Opts' on
%% the generic form covers every new Glasbox-unresolved rule that
%% would otherwise flip the kernel into rejecting the whole batch.
-spec expanded_rule_has_unresolved(term()) -> boolean().
expanded_rule_has_unresolved({rule, _Verdict, Opts}) when is_map(Opts) ->
    has_unresolved(Opts);
expanded_rule_has_unresolved({_Tag, Opts}) when is_map(Opts) ->
    has_unresolved(Opts);
expanded_rule_has_unresolved(_) ->
    false.
