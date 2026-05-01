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

-module(erlkoenig_ct_firewall_tests).

-include_lib("eunit/include/eunit.hrl").

%% ============================================================
%% Phase 6.0c: nflog_group_for_zone/1 deterministic per-zone group
%% ============================================================
%%
%% Regression coverage for the Phase 6.0c receiver-leak: every
%% `apply_zone_chains/2' call previously allocated a fresh NFLOG
%% group via `next_nflog_group/0', spawning a new gen_server per
%% reload. The fix introduces an ETS-keyed mapping zone → group
%% so that reload reuses the same group (and the same receiver
%% via `erlkoenig_nft_nflog:ensure_started/1').

nflog_group_for_zone_test_() ->
    [
        {"same zone returns same group across calls",
         fun t_same_zone_same_group/0},
        {"different zones return different groups",
         fun t_different_zones_different_groups/0},
        {"reused zone does not advance the global counter",
         fun t_reuse_doesnt_advance_counter/0},
        {"existing zone mapping wins",
         fun t_existing_zone_mapping_wins/0}
    ].

t_same_zone_same_group() ->
    reset_ets(),
    G1 = erlkoenig_ct_firewall:nflog_group_for_zone(<<"prod">>),
    G2 = erlkoenig_ct_firewall:nflog_group_for_zone(<<"prod">>),
    G3 = erlkoenig_ct_firewall:nflog_group_for_zone(<<"prod">>),
    ?assertEqual(G1, G2),
    ?assertEqual(G1, G3).

t_different_zones_different_groups() ->
    reset_ets(),
    G_a = erlkoenig_ct_firewall:nflog_group_for_zone(<<"a">>),
    G_b = erlkoenig_ct_firewall:nflog_group_for_zone(<<"b">>),
    ?assertNotEqual(G_a, G_b).

t_reuse_doesnt_advance_counter() ->
    reset_ets(),
    %% First allocation seeds the counter.
    G_first = erlkoenig_ct_firewall:nflog_group_for_zone(<<"alpha">>),
    %% Re-using the same zone must NOT advance the counter, otherwise
    %% the next zone allocation would skip a value (the leak we're
    %% fixing).
    G_first = erlkoenig_ct_firewall:nflog_group_for_zone(<<"alpha">>),
    G_first = erlkoenig_ct_firewall:nflog_group_for_zone(<<"alpha">>),
    G_next = erlkoenig_ct_firewall:nflog_group_for_zone(<<"beta">>),
    ?assertEqual(G_first + 1, G_next).

t_existing_zone_mapping_wins() ->
    reset_ets(),
    _ = erlkoenig_ct_firewall:nflog_group_for_zone(<<"seed">>),
    true = ets:insert(erlkoenig_firewall_ports,
                      {{zone_nflog, <<"prod">>}, 4242}),
    ?assertEqual(4242, erlkoenig_ct_firewall:nflog_group_for_zone(<<"prod">>)).

%% ============================================================
%% Phase 6c: layout-aware setup batch
%% ============================================================
%%
%% Pure-helper tests for `build_setup_msgs/3'. Verifying behaviour
%% against the kernel needs the integration harness; here we
%% inspect the produced batch to lock the shape contract:
%%   - one batch (atomic — no two-step setup that could leak a
%%     half-installed layout).
%%   - forward chain in `forward_table()'.
%%   - postrouting/prerouting/output chains in `nat_table()'.
%%   - zone and ct are distinct production tables after 6g.

build_setup_msgs_emits_zone_and_ct_table_adds_test() ->
    Fwd = <<"erlkoenig_zone">>,
    Nat = <<"erlkoenig_ct">>,
    Msgs = erlkoenig_ct_firewall:build_setup_msgs(Fwd, Nat, []),
    Bins = run_msgs(Msgs),
    %% Same chains as above but two distinct table adds.
    ?assertEqual(7, length(Msgs)),
    ?assertEqual(1, count_table_adds(Bins, Fwd)),
    ?assertEqual(1, count_table_adds(Bins, Nat)).

build_setup_msgs_routes_chains_per_owner_table_test() ->
    Fwd = <<"erlkoenig_zone">>,
    Nat = <<"erlkoenig_ct">>,
    Msgs = erlkoenig_ct_firewall:build_setup_msgs(Fwd, Nat, []),
    Bins = run_msgs(Msgs),
    %% The forward chain name must appear *only* in the bytes that
    %% carry the forward table; the NAT chains (postrouting, etc.)
    %% must appear *only* in bytes carrying the NAT table.
    {FwdBins, NatBins} = partition_by_table(Bins, Fwd, Nat),
    ?assert(any_match(FwdBins, <<"forward">>)),
    ?assertNot(any_match(NatBins, <<"forward">>)),
    ?assert(any_match(NatBins, <<"prerouting">>)),
    ?assert(any_match(NatBins, <<"postrouting">>)),
    ?assert(any_match(NatBins, <<"output">>)),
    ?assertNot(any_match(FwdBins, <<"prerouting">>)).

build_setup_msgs_appends_extra_test() ->
    Fwd = <<"erlkoenig_zone">>,
    Nat = <<"erlkoenig_ct">>,
    Extra = [fun(_S) -> <<>> end],
    Msgs = erlkoenig_ct_firewall:build_setup_msgs(Fwd, Nat, Extra),
    ?assertEqual(8, length(Msgs)),
    ?assertEqual(hd(lists:reverse(Msgs)), hd(Extra)).

%% ============================================================
%% Phase 6g: owner tables are fixed
%% ============================================================

forward_table_returns_zone_table_test() ->
    ?assertEqual(<<"erlkoenig_zone">>,
                 erlkoenig_ct_firewall:forward_table()).

nat_table_returns_ct_table_test() ->
    ?assertEqual(<<"erlkoenig_ct">>,
                 erlkoenig_ct_firewall:nat_table()).

build_setup_msgs_from_helpers_emits_zone_and_ct_tables_test() ->
    Fwd = erlkoenig_ct_firewall:forward_table(),
    Nat = erlkoenig_ct_firewall:nat_table(),
    ?assertEqual(<<"erlkoenig_zone">>, Fwd),
    ?assertEqual(<<"erlkoenig_ct">>, Nat),
    Msgs = erlkoenig_ct_firewall:build_setup_msgs(Fwd, Nat, []),
    ?assertEqual(7, length(Msgs)),
    Bins = run_msgs(Msgs),
    ?assertEqual(1, count_table_adds(Bins, Fwd)),
    ?assertEqual(1, count_table_adds(Bins, Nat)),
    ?assertEqual(0, count_table_adds(Bins, <<"erlkoenig">>)).

build_setup_msgs_from_helpers_routes_forward_chain_into_zone_test() ->
    Fwd = erlkoenig_ct_firewall:forward_table(),
    Nat = erlkoenig_ct_firewall:nat_table(),
    Msgs = erlkoenig_ct_firewall:build_setup_msgs(Fwd, Nat, []),
    Bins = run_msgs(Msgs),
    {FwdBins, NatBins} = partition_by_table(Bins, Fwd, Nat),
    ?assert(any_match(FwdBins, <<"forward">>)),
    ?assertNot(any_match(NatBins, <<"forward">>)),
    ?assert(any_match(NatBins, <<"prerouting">>)),
    ?assert(any_match(NatBins, <<"postrouting">>)),
    ?assertNot(any_match(FwdBins, <<"prerouting">>)).

%% --- helpers ---

%% Drive each msg-fun with a synthetic sequence and collect the
%% raw bytes. We match table names against these bytes — the
%% NLA payload encodes the table name as a NUL-terminated string
%% so a binary search finds it reliably.
run_msgs(Msgs) ->
    [Fun(1) || Fun <- Msgs].

count_table_adds(Bins, Table) ->
    %% Each `nft_table:add' message carries the table name with a
    %% known NLA prefix. Counting binary occurrences of the
    %% NUL-terminated table name is enough — no other message
    %% type repeats the table name in the same byte sequence.
    Needle = <<Table/binary, 0>>,
    length([B || B <- Bins, binary:match(B, Needle) =/= nomatch,
                 is_table_msg(B)]).

is_table_msg(Bin) ->
    %% nf_tables NEWTABLE has subsys=NFNL_SUBSYS_NFTABLES (10) and
    %% type=NFT_MSG_NEWTABLE (0): combined 16-bit type field is
    %% (10 << 8) | 0 = 2560 little-endian (0x00, 0x0a).
    case Bin of
        <<_Len:32/little, 0:8, 10:8, _/binary>> -> true;
        _ -> false
    end.

partition_by_table(Bins, FwdTable, NatTable) ->
    FwdNeedle = <<FwdTable/binary, 0>>,
    NatNeedle = <<NatTable/binary, 0>>,
    lists:foldl(
        fun(Bin, {F, N}) ->
            FInBin = binary:match(Bin, FwdNeedle) =/= nomatch,
            NInBin = binary:match(Bin, NatNeedle) =/= nomatch,
            case {FInBin, NInBin} of
                {true, false}  -> {[Bin | F], N};
                {false, true}  -> {F, [Bin | N]};
                _              -> {F, N}
            end
        end,
        {[], []},
        Bins
    ).

any_match(Bins, Needle) ->
    lists:any(fun(B) -> binary:match(B, Needle) =/= nomatch end, Bins).

%% --- helpers ---

reset_ets() ->
    case ets:whereis(erlkoenig_firewall_ports) of
        undefined -> ok;
        _Tid ->
            try ets:delete(erlkoenig_firewall_ports)
            catch error:badarg -> ok
            end
    end.
