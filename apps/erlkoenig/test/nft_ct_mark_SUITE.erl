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

-module(nft_ct_mark_SUITE).
-moduledoc """
Tests for conntrack mark (ct mark) support.

Unit group: verify ct mark IR terms and encoding.
Kernel group: apply ct mark set/match rules and verify with nft -j.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_ctmark">>).
-define(CHAIN, <<"input">>).
-define(REG1, 1).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            ir_ct_mark_read,
            ir_ct_mark_write,
            encode_ct_mark_read,
            encode_ct_mark_write,
            rules_ct_mark_set,
            rules_ct_mark_match
        ]},
        {kernel, [], [
            kernel_ct_mark_set_rule,
            kernel_ct_mark_match_rule
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
%% Unit tests — IR terms
%% ===================================================================

ir_ct_mark_read(_) ->
    %% ct_mark/1 produces a ct expression with dreg (read mode)
    Term = nft_expr_ir:ct_mark(?REG1),
    ?assertMatch({ct, #{key := mark, dreg := ?REG1}}, Term).

ir_ct_mark_write(_) ->
    %% ct_mark_set/1 produces a ct expression with sreg (write mode)
    Term = nft_expr_ir:ct_mark_set(?REG1),
    ?assertMatch({ct, #{key := mark, sreg := ?REG1}}, Term).

%% ===================================================================
%% Unit tests — Encoding
%% ===================================================================

encode_ct_mark_read(_) ->
    %% Encoding ct mark read should produce a ct expression with dreg and key=mark(3)
    Term = nft_expr_ir:ct_mark(?REG1),
    {<<"ct">>, Attrs} = encode_decode(Term),
    %% dreg=1
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),
    %% key=mark(3)
    ?assertMatch({2, <<3:32/big>>}, lists:keyfind(2, 1, Attrs)).

encode_ct_mark_write(_) ->
    %% Encoding ct mark write should produce a ct expression with sreg and key=mark(3)
    Term = nft_expr_ir:ct_mark_set(?REG1),
    {<<"ct">>, Attrs} = encode_decode(Term),
    %% sreg=1
    ?assertMatch({4, <<1:32/big>>}, lists:keyfind(4, 1, Attrs)),
    %% key=mark(3)
    ?assertMatch({2, <<3:32/big>>}, lists:keyfind(2, 1, Attrs)).

%% ===================================================================
%% Unit tests — Rule builders
%% ===================================================================

rules_ct_mark_set(_) ->
    Rule = nft_rules:ct_mark_set(16#42),
    ?assertEqual(2, length(Rule)),
    %% First expression: load immediate value into reg
    ?assertMatch({immediate, #{dreg := ?REG1, data := _}}, lists:nth(1, Rule)),
    %% Second expression: ct set mark from reg
    ?assertMatch({ct, #{key := mark, sreg := ?REG1}}, lists:nth(2, Rule)).

rules_ct_mark_match(_) ->
    Rule = nft_rules:ct_mark_match(16#01, nft_expr_ir:accept()),
    ?assertEqual(3, length(Rule)),
    %% First: load ct mark into reg
    ?assertMatch({ct, #{key := mark, dreg := ?REG1}}, lists:nth(1, Rule)),
    %% Second: compare
    ?assertMatch({cmp, #{sreg := ?REG1, op := eq}}, lists:nth(2, Rule)),
    %% Third: verdict
    ?assertMatch({immediate, #{verdict := accept}}, lists:nth(3, Rule)).

%% ===================================================================
%% Kernel tests
%% ===================================================================

kernel_ct_mark_set_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    Rule = nft_rules:ct_mark_set(16#42),
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
    %% Find rule entries that contain ct expressions
    RuleItems = [R || #{<<"rule">> := R} <- Items],
    ?assert(length(RuleItems) > 0),
    %% Verify the rule's expression list contains a ct expression
    [#{<<"expr">> := Exprs}] = RuleItems,
    %% nft JSON wraps ct expressions inside "mangle" or "match" objects
    ExprJson = iolist_to_binary(json:encode(Exprs)),
    ?assert(binary:match(ExprJson, <<"ct">>) =/= nomatch),
    nfnl_server:stop(Pid).

kernel_ct_mark_match_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    Rule = nft_rules:ct_mark_match(16#01, nft_expr_ir:accept()),
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
    RuleItems = [R || #{<<"rule">> := R} <- Items],
    ?assert(length(RuleItems) > 0),
    [#{<<"expr">> := Exprs}] = RuleItems,
    %% nft JSON wraps ct expressions inside "match" objects
    ExprJson = iolist_to_binary(json:encode(Exprs)),
    ?assert(binary:match(ExprJson, <<"ct">>) =/= nomatch),
    nfnl_server:stop(Pid).

%% ===================================================================
%% Helpers
%% ===================================================================

encode_decode(Term) ->
    Bin = nft_encode:expr(Term),
    Decoded = nfnl_attr:decode(Bin),
    {1, NameBin} = lists:keyfind(1, 1, Decoded),
    NameLen = byte_size(NameBin) - 1,
    <<Name:NameLen/binary, 0>> = NameBin,
    {2, nested, Attrs} = lists:keyfind(2, 1, Decoded),
    {Name, Attrs}.

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
