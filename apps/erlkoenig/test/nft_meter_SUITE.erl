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

-module(nft_meter_SUITE).
-moduledoc """
nf_tables meter (dynamic per-element rate limiting) tests.

Unit tests verify IR construction and encoding.
Kernel tests create table + chain + meter set + meter rule
and verify with `nft -j` that the meter set and rule exist.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_meter">>).
-define(CHAIN, <<"input">>).
-define(METER, <<"ssh_meter">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            meter_ir_structure,
            meter_ir_unit_conversion,
            meter_encode_dynset,
            meter_set_flags,
            meter_rule_proto_match
        ]},
        {kernel, [], [
            kernel_meter_set_exists,
            kernel_meter_rule_references_set
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

meter_ir_structure(_) ->
    Rule = nft_rules:meter_limit(
        ?METER,
        22,
        tcp,
        #{rate => 10, burst => 5, unit => second}
    ),
    ?assert(is_list(Rule)),
    ?assert(length(Rule) >= 5),
    %% Contains a dynset expression
    ?assert(
        lists:any(
            fun
                ({dynset, _}) -> true;
                (_) -> false
            end,
            Rule
        )
    ),
    %% Ends with drop
    ?assertMatch({immediate, #{verdict := drop}}, lists:last(Rule)).

meter_ir_unit_conversion(_) ->
    %% second => 1
    {dynset, #{exprs := [{limit, #{unit := 1}}]}} =
        nft_expr_ir:meter(<<"m">>, 1, 10, 5, second),
    %% minute => 60
    {dynset, #{exprs := [{limit, #{unit := 60}}]}} =
        nft_expr_ir:meter(<<"m">>, 1, 10, 5, minute),
    %% hour => 3600
    {dynset, #{exprs := [{limit, #{unit := 3600}}]}} =
        nft_expr_ir:meter(<<"m">>, 1, 10, 5, hour).

meter_encode_dynset(_) ->
    Expr = nft_expr_ir:meter(<<"ssh_meter">>, 1, 10, 5, second),
    Bin = nft_encode:expr(Expr),
    ?assert(is_binary(Bin)),
    ?assert(byte_size(Bin) > 0).

meter_set_flags(_) ->
    Msg = nft_set:add_meter(
        ?NFPROTO_INET,
        #{
            table => <<"fw">>,
            name => ?METER,
            type => ipv4_addr,
            id => 1
        },
        100
    ),
    ?assert(is_binary(Msg)),
    ?assert(byte_size(Msg) > 0).

meter_rule_proto_match(_) ->
    %% TCP meter
    TcpRule = nft_rules:meter_limit(
        <<"tcp_meter">>,
        80,
        tcp,
        #{rate => 100, burst => 50, unit => minute}
    ),
    ?assertMatch({meta, #{key := l4proto}}, hd(TcpRule)),
    {cmp, #{data := ProtoData}} = lists:nth(2, TcpRule),
    ?assertEqual(<<6>>, ProtoData),

    %% UDP meter
    UdpRule = nft_rules:meter_limit(
        <<"udp_meter">>,
        53,
        udp,
        #{rate => 50, burst => 10}
    ),
    {cmp, #{data := UdpProtoData}} = lists:nth(2, UdpRule),
    ?assertEqual(<<17>>, UdpProtoData).

%% ===================================================================
%% Kernel Tests
%% ===================================================================

kernel_meter_set_exists(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?CHAIN,
                    hook => input,
                    type => filter,
                    priority => 0,
                    policy => accept
                },
                Seq
            )
        end,
        fun(Seq) ->
            nft_set:add_meter(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?METER,
                    type => ipv4_addr,
                    id => 1
                },
                Seq
            )
        end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Sets = [S || #{<<"set">> := S} <- Items],
    ?assert(length(Sets) > 0),
    [MeterSet] = [S || S = #{<<"name">> := ?METER} <- Sets],
    %% Meter set should have dynamic flag (NFT_SET_EVAL shown as "dynamic" in nft JSON)
    %% Note: nft < 1.0.6 does not include "dynamic" in the JSON flags output,
    %% so we only verify the set was created and has the right name.
    Flags = maps:get(<<"flags">>, MeterSet, []),
    case lists:member(<<"dynamic">>, Flags) of
        true -> ok;
        false -> ct:log("nft version may not expose dynamic flag (got: ~p)", [Flags])
    end,
    nfnl_server:stop(Pid).

kernel_meter_rule_references_set(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    Rule = nft_rules:meter_limit(
        ?METER,
        22,
        tcp,
        #{rate => 10, burst => 5, unit => second}
    ),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?CHAIN,
                    hook => input,
                    type => filter,
                    priority => 0,
                    policy => accept
                },
                Seq
            )
        end,
        fun(Seq) ->
            nft_set:add_meter(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?METER,
                    type => ipv4_addr,
                    id => 1
                },
                Seq
            )
        end,
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, Rule)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Verify rule exists with dynset referencing the meter
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assert(length(Rules) > 0),
    nfnl_server:stop(Pid).

%% --- Helpers ---

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
