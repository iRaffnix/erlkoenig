%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%%

-module(erlkoenig_config_nft_tests).

-include_lib("eunit/include/eunit.hrl").

%% ============================================================
%% Phase 6f: owner-local ban-set registry
%% ============================================================

ban_set_entries_include_family_specific_owner_sets_test() ->
    Table = #{
        ban_set => #{ipv4 => <<"blocklist">>, ipv6 => <<"blocklist6">>},
        sets => [
            {<<"blocklist">>, ipv4_addr, #{flags => [timeout]}},
            {<<"blocklist6">>, ipv6_addr, #{flags => [timeout]}},
            {<<"allowlist">>, ipv4_addr}
        ]
    },
    ?assertEqual(
        [#{table => <<"erlkoenig_zone">>, set => <<"blocklist">>, type => ipv4_addr},
         #{table => <<"erlkoenig_zone">>, set => <<"blocklist6">>, type => ipv6_addr}],
        erlkoenig_config_nft:ban_set_entries(<<"erlkoenig_zone">>, Table)).

ban_set_entries_single_binary_is_ipv4_only_test() ->
    Table = #{
        ban_set => <<"blocklist">>,
        sets => [
            {<<"blocklist">>, ipv4_addr, #{flags => [timeout]}},
            {<<"blocklist6">>, ipv6_addr, #{flags => [timeout]}}
        ]
    },
    ?assertEqual(
        [#{table => <<"erlkoenig_zone">>, set => <<"blocklist">>, type => ipv4_addr}],
        erlkoenig_config_nft:ban_set_entries(<<"erlkoenig_zone">>, Table)).

ban_set_entries_skip_type_mismatches_test() ->
    Table = #{
        ban_set => #{ipv4 => <<"blocklist6">>, ipv6 => <<"blocklist">>},
        sets => [
            {<<"blocklist">>, ipv4_addr},
            {<<"blocklist6">>, ipv6_addr}
        ]
    },
    ?assertEqual([],
        erlkoenig_config_nft:ban_set_entries(<<"erlkoenig_zone">>, Table)).

ban_set_entries_skip_invalid_names_test() ->
    Table = #{
        ban_set => #{ipv4 => not_iolist},
        sets => [{<<"blocklist">>, ipv4_addr}]
    },
    ?assertEqual([],
        erlkoenig_config_nft:ban_set_entries(<<"erlkoenig_zone">>, Table)).

ban_set_targets_filter_by_ip_family_and_deduplicate_test() ->
    Key = erlkoenig_dsl_ban_sets,
    persistent_term:put(Key, #{
        <<"erlkoenig_host">> => [
            #{table => <<"erlkoenig_host">>, set => <<"blocklist">>, type => ipv4_addr}
        ],
        <<"erlkoenig_zone">> => [
            #{table => <<"erlkoenig_zone">>, set => <<"blocklist">>, type => ipv4_addr},
            #{table => <<"erlkoenig_zone">>, set => <<"blocklist">>, type => ipv4_addr},
            #{table => <<"erlkoenig_zone">>, set => <<"blocklist6">>, type => ipv6_addr}
        ]
    }),
    try
        ?assertEqual(
            [{<<"erlkoenig_host">>, <<"blocklist">>},
             {<<"erlkoenig_zone">>, <<"blocklist">>}],
            erlkoenig_config_nft:ban_set_targets(<<10, 0, 0, 1>>)),
        ?assertEqual(
            [{<<"erlkoenig_zone">>, <<"blocklist6">>}],
            erlkoenig_config_nft:ban_set_targets(<<16#20,16#01,16#0d,16#b8,
                                                  0,0,0,0,0,0,0,0,0,0,0,1>>))
    after
        persistent_term:erase(Key)
    end.

unknown_nft_table_is_refused_before_apply_test() ->
    Table = #{name => <<"erlkoenig">>, chains => []},
    ?assertMatch(
        {error, {unknown_nft_table, <<"erlkoenig">>, _}},
        erlkoenig_config_nft:apply_nft_tables([Table], #{}, #{}, [], [])).

%% ============================================================
%% Phase 6e.1.b: build_forward_topology_msgs/3 — pure shape +
%% reload-idempotency contract
%% ============================================================
%%
%% These tests drive the pure helper directly with synthetic
%% input. The goal is to pin three properties of the produced
%% batch:
%%
%%   (a) Deterministic byte sequence — same input twice yields
%%       byte-identical messages (modulo netlink sequence).
%%       This is the foundation for kernel-side reload
%%       idempotency: a deterministic batch with `flush_chain`
%%       before each rule-set produces an identical kernel state
%%       on every apply.
%%
%%   (b) Structural ordering — `flush_chain forward` precedes any
%%       add-rule into forward; `add chain X` precedes
%%       `flush chain X` precedes any add-rule into X. A jump
%%       rule in forward cannot precede the add of its target
%%       chain.
%%
%%   (c) No-duplicates — each regular chain (zone_*, pod_*) is
%%       added exactly once and jumped from forward exactly once,
%%       no matter how many times the batch is built.
%%
%% These together pin the kernel-side "no rule accumulation on
%% reload" property (§9.1 6e.1.b criterion (b)) without needing a
%% live kernel harness — the kernel's atomic batch apply
%% guarantees the rest. NFLOG-failure path is tested separately
%% against `apply_forward_topology/4`.

%% --- Test fixtures ---

simple_zone() ->
    #{
        name => <<"alpha">>,
        bridge => <<"ek_br_alpha">>,
        chains => [
            #{
                hook => forward,
                rules => [
                    {rule, accept, #{tcp => #{dport => 80}}},
                    {rule, drop, #{}}
                ]
            }
        ]
    }.

second_zone() ->
    #{
        name => <<"beta">>,
        bridge => <<"ek_br_beta">>,
        chains => [
            #{hook => forward, rules => [{rule, accept, #{}}]}
        ]
    }.

empty_zone() ->
    #{
        name => <<"empty">>,
        bridge => <<"ek_br_empty">>,
        chains => [#{hook => forward, rules => []}]
    }.

ctx_for(Zones) ->
    %% Synthetic NflogGroups map. Production code resolves the
    %% group via `erlkoenig_ct_firewall:nflog_group_for_zone/1`,
    %% but the pure helper only consumes the resolved map, so the
    %% test fixture passes one in directly.
    NflogGroups = lists:foldl(
        fun(Z, Acc) ->
            ZoneName = maps:get(name, Z),
            Acc#{ZoneName => 100 + erlang:phash2(ZoneName, 1000)}
        end, #{}, Zones),
    #{
        ip_map => #{},
        running_map => #{},
        zone_nflog_groups => NflogGroups,
        fwd_table => <<"erlkoenig_zone">>
    }.

run_msgs(Msgs) ->
    [Fun(Seq) || {Fun, Seq} <- lists:zip(Msgs, lists:seq(1, length(Msgs)))].

%% --- (a) Determinism: same input twice → identical bytes ---

build_forward_topology_is_deterministic_test() ->
    Zones = [simple_zone()],
    Pods = [],
    Ctx = ctx_for(Zones),
    Msgs1 = erlkoenig_config_nft:build_forward_topology_msgs(Zones, Pods, Ctx),
    Msgs2 = erlkoenig_config_nft:build_forward_topology_msgs(Zones, Pods, Ctx),
    %% Same number of messages.
    ?assertEqual(length(Msgs1), length(Msgs2)),
    %% Same bytes when driven with the same sequence numbers.
    Bins1 = run_msgs(Msgs1),
    Bins2 = run_msgs(Msgs2),
    ?assertEqual(Bins1, Bins2).

build_forward_topology_is_deterministic_two_zones_test() ->
    Zones = [simple_zone(), second_zone()],
    Pods = [],
    Ctx = ctx_for(Zones),
    Bins1 = run_msgs(erlkoenig_config_nft:build_forward_topology_msgs(
                        Zones, Pods, Ctx)),
    Bins2 = run_msgs(erlkoenig_config_nft:build_forward_topology_msgs(
                        Zones, Pods, Ctx)),
    ?assertEqual(Bins1, Bins2).

%% --- (b) Structural ordering ---

forward_flush_is_first_message_test() ->
    %% The forward base chain flush must be the first netlink
    %% message in the batch, otherwise a stale rule from before
    %% the apply could match before the flush takes effect within
    %% the atomic transaction.
    Zones = [simple_zone()],
    Ctx = ctx_for(Zones),
    [FirstMsg | _] = erlkoenig_config_nft:build_forward_topology_msgs(
                       Zones, [], Ctx),
    Bin = FirstMsg(1),
    %% NFT_MSG_DELRULE has subsys=10 (NFNL_SUBSYS_NFTABLES) and
    %% type=8 (NFT_MSG_DELRULE). The 16-bit type field encoded
    %% little-endian is <<8, 10>>.
    ?assertMatch(<<_Len:32/little, 8:8, 10:8, _/binary>>, Bin),
    %% Forward chain name is in the payload.
    ?assertNotEqual(nomatch, binary:match(Bin, <<"forward">>)).

regular_chain_add_precedes_flush_test() ->
    %% For each zone_* and pod_* regular chain in the batch, the
    %% NEWCHAIN add must appear before the DELRULE flush of the
    %% same chain. Otherwise the kernel would receive a flush of
    %% a non-existent chain (ENOENT) and roll the entire batch
    %% back.
    Zones = [simple_zone(), second_zone()],
    Ctx = ctx_for(Zones),
    Msgs = erlkoenig_config_nft:build_forward_topology_msgs(Zones, [], Ctx),
    Bins = run_msgs(Msgs),
    AlphaAddIdx = first_msg_with(Bins, fun is_newchain/1, <<"zone_alpha">>),
    AlphaFlushIdx = first_msg_with(Bins, fun is_delrule/1, <<"zone_alpha">>),
    BetaAddIdx = first_msg_with(Bins, fun is_newchain/1, <<"zone_beta">>),
    BetaFlushIdx = first_msg_with(Bins, fun is_delrule/1, <<"zone_beta">>),
    ?assert(AlphaAddIdx < AlphaFlushIdx),
    ?assert(BetaAddIdx < BetaFlushIdx).

forward_jump_follows_target_chain_creation_test() ->
    %% The jump rule in forward → zone_alpha must come after
    %% zone_alpha is added, otherwise the kernel rejects the
    %% jump as ENOENT (target chain missing).
    Zones = [simple_zone()],
    Ctx = ctx_for(Zones),
    Msgs = erlkoenig_config_nft:build_forward_topology_msgs(Zones, [], Ctx),
    Bins = run_msgs(Msgs),
    AddIdx = first_msg_with(Bins, fun is_newchain/1, <<"zone_alpha">>),
    %% Find the forward-jump rule (NEWRULE in forward chain
    %% mentioning zone_alpha as immediate verdict target).
    JumpIdx = first_msg_where(Bins, fun(B) ->
        is_newrule(B) andalso
        binary:match(B, <<"forward">>) =/= nomatch andalso
        binary:match(B, <<"zone_alpha">>) =/= nomatch
    end),
    ?assert(AddIdx < JumpIdx).

%% --- (c) No-duplicates ---

each_zone_chain_added_exactly_once_test() ->
    %% Even with two builds back-to-back, each regular chain
    %% appears exactly once per build (no double-add inside one
    %% batch). The kernel side-effect "second apply does not
    %% duplicate" follows from this plus the flush_chain that
    %% precedes per-chain rule adds.
    Zones = [simple_zone(), second_zone()],
    Ctx = ctx_for(Zones),
    Msgs = erlkoenig_config_nft:build_forward_topology_msgs(Zones, [], Ctx),
    Bins = run_msgs(Msgs),
    ?assertEqual(1, count_msgs(Bins, fun is_newchain/1, <<"zone_alpha">>)),
    ?assertEqual(1, count_msgs(Bins, fun is_newchain/1, <<"zone_beta">>)).

each_zone_jumped_at_most_once_in_forward_test() ->
    %% Per Spec §9.1 6e.1.b criterion (b): no duplicated forward
    %% jumps. Pin it by structural inspection — the forward jump
    %% rule for each zone appears exactly once per build.
    Zones = [simple_zone(), second_zone()],
    Ctx = ctx_for(Zones),
    Msgs = erlkoenig_config_nft:build_forward_topology_msgs(Zones, [], Ctx),
    Bins = run_msgs(Msgs),
    AlphaJumps = [B || B <- Bins,
                       is_newrule(B),
                       binary:match(B, <<"forward">>) =/= nomatch,
                       binary:match(B, <<"zone_alpha">>) =/= nomatch],
    BetaJumps = [B || B <- Bins,
                      is_newrule(B),
                      binary:match(B, <<"forward">>) =/= nomatch,
                      binary:match(B, <<"zone_beta">>) =/= nomatch],
    ?assertEqual(1, length(AlphaJumps)),
    ?assertEqual(1, length(BetaJumps)).

empty_zone_emits_no_chain_test() ->
    %% A zone whose chains carry no rules must not consume an
    %% NFLOG receiver, must not get a regular chain, and must
    %% not appear as a jump target in forward. Only zones with
    %% at least one rule are "active".
    Zones = [empty_zone()],
    Ctx = ctx_for(Zones),
    Msgs = erlkoenig_config_nft:build_forward_topology_msgs(Zones, [], Ctx),
    Bins = run_msgs(Msgs),
    ?assertEqual(0, count_msgs(Bins, fun is_newchain/1, <<"zone_empty">>)).

zero_zones_zero_pods_minimum_batch_test() ->
    %% Edge case: empty topology. The batch still flushes the
    %% forward base chain and re-adds ct_established_accept —
    %% the forward chain remains a valid base chain with the
    %% conntrack fast-path. No regular chains, no jumps.
    Ctx = ctx_for([]),
    Msgs = erlkoenig_config_nft:build_forward_topology_msgs([], [], Ctx),
    %% At minimum: 1 flush_forward + 1 ct_established_accept.
    ?assert(length(Msgs) >= 2),
    Bins = run_msgs(Msgs),
    %% No NEWCHAIN messages for any zone_* / pod_* regular chain.
    ?assertEqual(0, count_msgs(Bins, fun is_newchain/1, <<"zone_">>)),
    ?assertEqual(0, count_msgs(Bins, fun is_newchain/1, <<"pod_">>)).

%% --- helpers ---

%% nf_tables NL message types share subsys=10 (NFNL_SUBSYS_NFTABLES).
%% Type field is 16-bit little-endian: <<MsgType, Subsys>>.
is_newchain(<<_Len:32/little, 3:8, 10:8, _/binary>>) -> true;
is_newchain(_) -> false.

is_newrule(<<_Len:32/little, 6:8, 10:8, _/binary>>) -> true;
is_newrule(_) -> false.

is_delrule(<<_Len:32/little, 8:8, 10:8, _/binary>>) -> true;
is_delrule(_) -> false.

first_msg_with(Bins, Pred, Needle) ->
    first_msg_where(Bins, fun(B) ->
        Pred(B) andalso binary:match(B, Needle) =/= nomatch
    end).

first_msg_where(Bins, Pred) ->
    {Idx, _} = lists:foldl(
        fun(B, {undefined, I}) ->
                case Pred(B) of
                    true -> {I, I + 1};
                    false -> {undefined, I + 1}
                end;
           (_, {Found, I}) ->
                {Found, I + 1}
        end, {undefined, 0}, Bins),
    Idx.

count_msgs(Bins, Pred, Needle) ->
    length([B || B <- Bins,
                 Pred(B),
                 binary:match(B, Needle) =/= nomatch]).

%% ============================================================
%% Phase 6e.1.b: apply_forward_topology/4 — NFLOG fail-loud
%% ============================================================
%%
%% Glasbox: if any zone's NFLOG receiver fails to start, the
%% apply returns a structured error and **no** netlink batch is
%% sent. Otherwise we'd install drop+log rules whose log-side has
%% no observer — silent loss of audit signal.
%%
%% This is integration-shaped because `apply_forward_topology/4`
%% calls `erlkoenig_ct_firewall:nflog_group_for_zone/1` and then
%% `erlkoenig_nft_nflog:ensure_started/1`, both of which touch
%% live state. Pinning the contract end-to-end without spinning
%% up the full firewall stack means we let real `ensure_started`
%% run for a normal zone — it succeeds — and confirm the apply
%% does not blow up before the batch step.
%%
%% A negative test for the failure path would need to make
%% ensure_started fail deterministically; that's expensive in
%% pure eunit and is covered by the integration-level harness
%% in CI. Here we pin only the success path's structured
%% behavior — no batch installed when no `nfnl_server` is
%% running, the call returns `{error, {batch_failed, _}}`.

apply_forward_topology_returns_structured_error_when_no_nft_srv_test() ->
    %% No erlkoenig_nft_srv is running in this eunit context, so
    %% nfnl_server:apply_msgs will fail. The wrapper must wrap
    %% that failure in a structured tag, not let it crash the
    %% caller.
    %%
    %% The test passes a single empty-rules zone so
    %% `ensure_zone_nflogs/2` filters it out before even touching
    %% the NFLOG receiver — keeps this test focused on the
    %% batch-failure return shape.
    Zones = [empty_zone()],
    Pods = [],
    IpMap = #{},
    SpawnedPids = [],
    Result = erlkoenig_config_nft:apply_forward_topology(
        Zones, Pods, IpMap, SpawnedPids),
    ?assertMatch({error, {batch_failed, _}}, Result).

%% NFLOG fail-loud: when ensure_started returns an error, the
%% wrapper must abort with `{error, {nflog_start_failed, ...}}`
%% **before** the netlink batch is sent. Distinguishing this from
%% the batch-failed shape is the load-bearing assertion — the
%% specific error tag tells the operator that NO rules were
%% installed (we never reached apply_msgs), as opposed to a
%% partial-failure scenario.
%%
%% Pinned via the injectable NflogFun on
%% `apply_forward_topology/5`. A real failure of
%% `erlkoenig_nft_nflog:ensure_started/1` is hard to trigger
%% deterministically in eunit (it depends on netlink-socket
%% setup); the injected fun fails on demand.
apply_forward_topology_aborts_on_nflog_failure_test() ->
    Zones = [simple_zone()],
    Pods = [],
    IpMap = #{},
    SpawnedPids = [],
    %% Fail-fun: any group → error. The wrapper must surface this
    %% as `nflog_start_failed`, NOT as `batch_failed` — the
    %% latter would imply we reached the netlink batch step,
    %% which violates the contract.
    FailNflog = fun(_Group) -> {error, simulated_failure} end,
    Result = erlkoenig_config_nft:apply_forward_topology(
        Zones, Pods, IpMap, SpawnedPids, FailNflog),
    ?assertMatch({error, {nflog_start_failed, _ZoneName, _Group,
                          simulated_failure}}, Result),
    %% Pin the zone-name + reason in the structured error so
    %% downstream operators can attribute the failure.
    {error, {nflog_start_failed, ZoneName, _Group, Reason}} = Result,
    ?assertEqual(<<"alpha">>, ZoneName),
    ?assertEqual(simulated_failure, Reason).

apply_forward_topology_aborts_before_first_zone_in_multi_zone_test() ->
    %% Sequential ensure: a failure on the first zone short-circuits.
    %% Subsequent zones are not even attempted. The structured error
    %% identifies which zone tripped the failure.
    Zones = [simple_zone(), second_zone()],
    Pods = [],
    IpMap = #{},
    SpawnedPids = [],
    %% Track which zones ensure_started saw via process dict —
    %% test-local, no shared state across runs.
    erlang:put(nflog_calls_seen, []),
    TrackingFailNflog = fun(Group) ->
        Seen = erlang:get(nflog_calls_seen),
        erlang:put(nflog_calls_seen, Seen ++ [Group]),
        {error, simulated_failure}
    end,
    Result = erlkoenig_config_nft:apply_forward_topology(
        Zones, Pods, IpMap, SpawnedPids, TrackingFailNflog),
    ?assertMatch({error, {nflog_start_failed, <<"alpha">>, _, _}}, Result),
    %% Exactly one ensure_started call — the loop aborted on the
    %% first failure, never reached zone "beta".
    ?assertEqual(1, length(erlang:get(nflog_calls_seen))),
    erlang:erase(nflog_calls_seen).

%% ============================================================
%% Phase 6e.1.b: reload-semantic test via binary state-tracker
%% ============================================================
%%
%% The pure shape tests above pin determinism. To pin the kernel-
%% side "no rule accumulation on reload" property end-to-end —
%% without standing up a live kernel harness in eunit — we drive
%% the produced batch through a state-tracker that simulates the
%% relevant kernel transitions: NEWCHAIN adds a chain, DELRULE
%% (without a handle) flushes its rules, NEWRULE appends a rule.
%% Two consecutive applies of the same logical topology must
%% leave the simulated state structurally identical.
%%
%% The tracker only handles the message types this builder emits
%% — it is not a general nf_tables emulator.

reload_idempotency_via_state_tracker_test() ->
    Zones = [simple_zone(), second_zone()],
    Pods = [],
    Ctx = ctx_for(Zones),
    Apply1 = simulate_apply(
        erlkoenig_config_nft:build_forward_topology_msgs(Zones, Pods, Ctx)),
    %% Second apply on the state from the first apply — this is
    %% what the kernel sees on reload.
    Apply2 = simulate_apply_on(
        Apply1,
        erlkoenig_config_nft:build_forward_topology_msgs(Zones, Pods, Ctx)),
    %% Glasbox: same logical topology twice → identical state.
    ?assertEqual(Apply1, Apply2).

reload_no_duplicate_forward_jumps_test() ->
    %% Stronger statement: between the two applies the forward
    %% chain accumulates exactly the same number of rules — not
    %% double, not missing.
    Zones = [simple_zone(), second_zone()],
    Pods = [],
    Ctx = ctx_for(Zones),
    Apply1 = simulate_apply(
        erlkoenig_config_nft:build_forward_topology_msgs(Zones, Pods, Ctx)),
    Apply2 = simulate_apply_on(
        Apply1,
        erlkoenig_config_nft:build_forward_topology_msgs(Zones, Pods, Ctx)),
    Forward1 = maps:get(<<"forward">>, maps:get(rules, Apply1), []),
    Forward2 = maps:get(<<"forward">>, maps:get(rules, Apply2), []),
    ?assertEqual(length(Forward1), length(Forward2)).

reload_no_duplicate_regular_chain_rules_test() ->
    Zones = [simple_zone(), second_zone()],
    Pods = [],
    Ctx = ctx_for(Zones),
    Apply1 = simulate_apply(
        erlkoenig_config_nft:build_forward_topology_msgs(Zones, Pods, Ctx)),
    Apply2 = simulate_apply_on(
        Apply1,
        erlkoenig_config_nft:build_forward_topology_msgs(Zones, Pods, Ctx)),
    %% For each zone-regular chain, rule count must match across
    %% applies.
    lists:foreach(fun(ChainName) ->
        Rules1 = maps:get(ChainName, maps:get(rules, Apply1), []),
        Rules2 = maps:get(ChainName, maps:get(rules, Apply2), []),
        ?assertEqual(length(Rules1), length(Rules2))
    end, [<<"zone_alpha">>, <<"zone_beta">>]).

%% --- state-tracker helpers ---

%% Simulated kernel state:
%%   #{chains => set(ChainName), rules => #{ChainName => [RuleBytes]}}
%% NEWCHAIN inserts the chain name; DELRULE without a handle
%% clears the per-chain rule list; NEWRULE appends to the
%% per-chain rule list. Rule identity for "no duplicates" is the
%% encoded rule body — we do not attempt to parse expressions.
simulate_apply(Msgs) ->
    simulate_apply_on(#{chains => sets:new(), rules => #{}}, Msgs).

simulate_apply_on(State, Msgs) ->
    Bins = run_msgs(Msgs),
    lists:foldl(fun(B, S) -> apply_msg(B, S) end, State, Bins).

apply_msg(Bin, State) ->
    case classify_msg(Bin) of
        {newchain, ChainName} ->
            #{chains := Cs} = State,
            State#{chains => sets:add_element(ChainName, Cs)};
        {delrule, ChainName} ->
            %% Kernel semantics: DELRULE without a handle attribute
            %% clears all rules in (table, chain). The tracker
            %% mirrors that.
            #{rules := Rs} = State,
            State#{rules => Rs#{ChainName => []}};
        {newrule, ChainName} ->
            #{rules := Rs} = State,
            Existing = maps:get(ChainName, Rs, []),
            State#{rules => Rs#{ChainName => Existing ++ [Bin]}};
        unknown ->
            State
    end.

%% Classify by the 16-bit type field (subsys=10, msgtype lo-byte).
%% NEWCHAIN=3, NEWRULE=6, DELRULE=8.
classify_msg(<<_Len:32/little, 3:8, 10:8, _/binary>> = Bin) ->
    {newchain, extract_chain_name(Bin)};
classify_msg(<<_Len:32/little, 6:8, 10:8, _/binary>> = Bin) ->
    {newrule, extract_chain_name(Bin)};
classify_msg(<<_Len:32/little, 8:8, 10:8, _/binary>> = Bin) ->
    {delrule, extract_chain_name(Bin)};
classify_msg(_) ->
    unknown.

%% NFTA_*_CHAIN attribute carries the chain name as a NUL-terminated
%% string. The first known chain name ("forward", "zone_*", "pod_*")
%% appearing in the payload identifies the chain. We do not parse
%% attribute headers explicitly — the binary search is sufficient
%% because no other field contains these patterns in this builder's
%% output.
extract_chain_name(Bin) ->
    Candidates = [<<"forward">>,
                  <<"zone_alpha">>, <<"zone_beta">>, <<"zone_empty">>,
                  <<"pod_test_0">>, <<"pod_test_1">>],
    case first_match(Bin, Candidates) of
        nomatch -> <<"?">>;
        Name -> Name
    end.

first_match(_Bin, []) -> nomatch;
first_match(Bin, [Cand | Rest]) ->
    case binary:match(Bin, Cand) of
        nomatch -> first_match(Bin, Rest);
        _ -> Cand
    end.

%% ============================================================
%% Phase 6e.1.b: port-forward zone-side shape
%% ============================================================
%%
%% The topology builder is responsible for the zone-side half of
%% a port-forward: a jump from the forward base chain to a
%% per-pod regular chain, and an accept rule (matching the
%% port) inside that chain. The matching ct-side DNAT is
%% installed by `erlkoenig_ct_firewall`'s container path, not
%% here — see Spec §9.1 6e.1.b (d). End-to-end coverage of both
%% halves belongs in an integration harness; this test pins the
%% builder's contribution to the shape.

port_forward_pod() ->
    #{
        name => <<"test">>,
        containers => [#{name => <<"ct1">>, replicas => 1}],
        chains => [
            #{rules => [
                {rule, accept, #{tcp => #{dport => 8080}}}
            ]}
        ]
    }.

port_forward_zone_side_shape_test() ->
    Pods = [port_forward_pod()],
    Zones = [],
    Ctx = ctx_for([]),
    Msgs = erlkoenig_config_nft:build_forward_topology_msgs(Zones, Pods, Ctx),
    Bins = run_msgs(Msgs),
    %% (i) Pod regular chain `pod_test_0` is created.
    ?assertEqual(1, count_msgs(Bins, fun is_newchain/1, <<"pod_test_0">>)),
    %% (ii) Forward base chain has a jump rule whose body
    %% mentions `pod_test_0` (the immediate verdict's chain
    %% name).
    ForwardJumps = [B || B <- Bins,
                         is_newrule(B),
                         binary:match(B, <<"forward">>) =/= nomatch,
                         binary:match(B, <<"pod_test_0">>) =/= nomatch],
    ?assertEqual(1, length(ForwardJumps)),
    %% (iii) The pod chain itself carries an accept rule with
    %% the requested dport. NEWRULE in `pod_test_0` exists.
    PodRules = [B || B <- Bins,
                     is_newrule(B),
                     binary:match(B, <<"pod_test_0">>) =/= nomatch,
                     binary:match(B, <<"forward">>) =:= nomatch],
    ?assert(length(PodRules) >= 1).
