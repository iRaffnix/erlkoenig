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

-module(nft_queue_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_queue">>).
-define(CHAIN, <<"input">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            encode_queue_basic,
            encode_queue_with_total,
            encode_queue_with_flags,
            encode_queue_bypass_fanout
        ]},
        {kernel, [], [
            kernel_queue_basic,
            kernel_queue_bypass,
            kernel_queue_fanout
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

%% --- Unit tests ---

encode_queue_basic(_) ->
    Expr = nft_expr_ir:queue(100),
    Bin = nft_encode:expr(Expr),
    ?assert(is_binary(Bin)),
    ?assert(byte_size(Bin) > 0).

encode_queue_with_total(_) ->
    Expr = nft_expr_ir:queue({100, 103}, #{flags => []}),
    ?assertMatch({queue, #{num := 100, total := 4, flags := 0}}, Expr),
    Bin = nft_encode:expr(Expr),
    ?assert(is_binary(Bin)),
    ?assert(byte_size(Bin) > 0).

encode_queue_with_flags(_) ->
    Expr = nft_expr_ir:queue(50, #{flags => [bypass]}),
    ?assertMatch({queue, #{num := 50, flags := 1}}, Expr),
    Bin = nft_encode:expr(Expr),
    ?assert(is_binary(Bin)).

encode_queue_bypass_fanout(_) ->
    Expr = nft_expr_ir:queue(10, #{flags => [bypass, fanout]}),
    ?assertMatch({queue, #{num := 10, flags := 3}}, Expr),
    Bin = nft_encode:expr(Expr),
    ?assert(is_binary(Bin)).

%% --- Kernel tests ---

kernel_queue_basic(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    Rule = nft_rules:queue_rule(53, udp, #{num => 100}),
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
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, Rule)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assert(length(Rules) > 0),
    [FirstRule | _] = Rules,
    Exprs = maps:get(<<"expr">>, FirstRule),
    QueueExprs = [E || #{<<"queue">> := _} = E <- Exprs],
    ?assert(length(QueueExprs) > 0),
    [#{<<"queue">> := QueueObj} | _] = QueueExprs,
    ?assertEqual(100, maps:get(<<"num">>, QueueObj)),
    nfnl_server:stop(Pid).

kernel_queue_bypass(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    Rule = nft_rules:queue_rule(80, tcp, #{num => 200, flags => [bypass]}),
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
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, Rule)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assert(length(Rules) > 0),
    [FirstRule | _] = Rules,
    Exprs = maps:get(<<"expr">>, FirstRule),
    QueueExprs = [E || #{<<"queue">> := _} = E <- Exprs],
    ?assert(length(QueueExprs) > 0),
    [#{<<"queue">> := QueueObj} | _] = QueueExprs,
    ?assertEqual(200, maps:get(<<"num">>, QueueObj)),
    %% nft -j reports bypass as a flag list or string
    Flags = maps:get(<<"flags">>, QueueObj, []),
    ?assert(Flags =/= []),
    nfnl_server:stop(Pid).

kernel_queue_fanout(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    Rule = nft_rules:queue_rule(443, tcp, #{num => 300, flags => [fanout]}),
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
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, Rule)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assert(length(Rules) > 0),
    [FirstRule | _] = Rules,
    Exprs = maps:get(<<"expr">>, FirstRule),
    QueueExprs = [E || #{<<"queue">> := _} = E <- Exprs],
    ?assert(length(QueueExprs) > 0),
    [#{<<"queue">> := QueueObj} | _] = QueueExprs,
    ?assertEqual(300, maps:get(<<"num">>, QueueObj)),
    Flags = maps:get(<<"flags">>, QueueObj, []),
    ?assert(Flags =/= []),
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
