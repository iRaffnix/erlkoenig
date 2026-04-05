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

-module(nft_vmap_SUITE).
-moduledoc """
Verdict map (vmap) tests for Erlkoenig.

Unit group: verify IR structure, vmap set flags, element encoding.
Kernel group: create table + vmap + chains + dispatch rule, verify with nft -j.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_vmap">>).
-define(CHAIN, <<"input">>).
-define(VMAP, <<"port_dispatch">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            ir_vmap_lookup_structure,
            ir_vmap_lookup_has_dreg_zero,
            vmap_set_has_map_flag,
            vmap_dispatch_rule_structure,
            vmap_elem_encoding
        ]},
        {kernel, [], [
            kernel_vmap_dispatch
        ]}
    ].

init_per_group(kernel, Config) ->
    case os:cmd("id -u") of
        "0\n" -> Config;
        _ -> {skip, "kernel tests require root"}
    end;
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    os:cmd("nft delete table inet " ++ binary_to_list(?TABLE) ++ " 2>/dev/null"),
    Config.

end_per_testcase(_TC, _Config) ->
    os:cmd("nft delete table inet " ++ binary_to_list(?TABLE) ++ " 2>/dev/null"),
    ok.

%% ===================================================================
%% Unit Tests
%% ===================================================================

ir_vmap_lookup_structure(_) ->
    Expr = nft_expr_ir:vmap_lookup(1, <<"my_vmap">>),
    ?assertMatch({lookup, #{sreg := 1, set := <<"my_vmap">>, dreg := 0}}, Expr).

ir_vmap_lookup_has_dreg_zero(_) ->
    {lookup, Opts} = nft_expr_ir:vmap_lookup(1, <<"test">>),
    ?assertEqual(0, maps:get(dreg, Opts)).

vmap_set_has_map_flag(_) ->
    Msg = nft_set:add_vmap(
        ?NFPROTO_INET,
        #{
            table => <<"fw">>,
            name => <<"pd">>,
            type => inet_service
        },
        1,
        100
    ),
    %% NFT_MSG_NEWSET = 9, type = (10 << 8) | 9 = 2569
    <<_Len:32/little, 2569:16/little, _/binary>> = Msg,
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    %% NFTA_SET_FLAGS(3) should have MAP bit (0x08)
    {3, <<Flags:32/big>>} = lists:keyfind(3, 1, Decoded),
    ?assertEqual(16#08, Flags band 16#08),
    %% NFTA_SET_DATA_TYPE(6) should be NFT_DATA_VERDICT (0xFFFFFF00)
    {6, <<DataType:32/big>>} = lists:keyfind(6, 1, Decoded),
    ?assertEqual(16#FFFFFF00, DataType).

vmap_dispatch_rule_structure(_) ->
    Rule = nft_rules:vmap_dispatch(tcp, <<"my_vmap">>),
    ?assertMatch(
        [
            {meta, #{key := l4proto, dreg := 1}},
            {cmp, #{sreg := 1, op := eq, data := <<6>>}},
            {payload, #{base := transport, offset := 2, len := 2, dreg := 1}},
            {lookup, #{sreg := 1, set := <<"my_vmap">>, dreg := 0}}
        ],
        Rule
    ).

vmap_elem_encoding(_) ->
    Msg = nft_set_elem:add_vmap_elems(
        ?NFPROTO_INET,
        <<"fw">>,
        <<"pd">>,
        [
            {<<22:16/big>>, {jump, <<"ssh_chain">>}},
            {<<80:16/big>>, accept}
        ],
        1
    ),
    %% NFT_MSG_NEWSETELEM = 12, type = (10 << 8) | 12 = 2572
    <<_Len:32/little, 2572:16/little, _/binary>> = Msg,
    ?assert(byte_size(Msg) > 20).

%% ===================================================================
%% Kernel Tests
%% ===================================================================

kernel_vmap_dispatch(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),

    %% Create table
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end
    ]),

    %% Create regular chains that the vmap will jump to
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) ->
            nft_chain:add_regular(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE, name => <<"ssh_chain">>
                },
                Seq
            )
        end,
        fun(Seq) ->
            nft_chain:add_regular(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE, name => <<"http_chain">>
                },
                Seq
            )
        end
    ]),

    %% Create the vmap set
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) ->
            nft_set:add_vmap(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?VMAP,
                    type => inet_service
                },
                1,
                Seq
            )
        end
    ]),

    %% Add vmap elements
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) ->
            nft_set_elem:add_vmap_elems(
                ?NFPROTO_INET,
                ?TABLE,
                ?VMAP,
                [
                    {<<22:16/big>>, {jump, <<"ssh_chain">>}},
                    {<<80:16/big>>, {jump, <<"http_chain">>}}
                ],
                Seq
            )
        end
    ]),

    %% Create base chain with dispatch rule
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?CHAIN,
                    hook => input,
                    type => filter,
                    priority => 100,
                    policy => accept
                },
                Seq
            )
        end,
        nft_encode:rule_fun(
            inet,
            ?TABLE,
            ?CHAIN,
            nft_rules:vmap_dispatch(tcp, ?VMAP)
        )
    ]),

    %% Verify structure with nft -j
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),

    %% Check vmap set exists and has map flag
    %% nft JSON lists verdict maps under "map", not "set"
    %% nft JSON lists verdict maps under "map" (not "set"),
    %% so being found here already proves the MAP flag is set.
    VmapSets = [S || #{<<"map">> := S = #{<<"name">> := ?VMAP}} <- Items],
    ?assertMatch([_], VmapSets),

    %% Check chains exist
    Chains = [C || #{<<"chain">> := C} <- Items],
    ChainNames = [maps:get(<<"name">>, C) || C <- Chains],
    ?assert(lists:member(<<"ssh_chain">>, ChainNames)),
    ?assert(lists:member(<<"http_chain">>, ChainNames)),

    %% Check dispatch rule exists
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assertMatch([_], Rules),

    nfnl_server:stop(Pid).

%% ===================================================================
%% Helpers
%% ===================================================================

nft_json(Cmd) ->
    case os:cmd("nft -j " ++ Cmd ++ " 2>/dev/null") of
        [] ->
            [];
        Output ->
            case catch json:decode(list_to_binary(Output)) of
                #{<<"nftables">> := Items} -> Items;
                _ -> ct:fail({nft_json_failed, Cmd, Output})
            end
    end.
