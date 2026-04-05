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

-module(nft_quota_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_quota">>).
-define(CHAIN, <<"input">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            quota_ir_term,
            quota_ir_objref,
            quota_encode,
            quota_object_encode,
            quota_rules_accept,
            quota_rules_drop
        ]},
        {kernel, [], [kernel_named_quota, kernel_quota_in_rule]}
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

quota_ir_term(_) ->
    Term = nft_expr_ir:quota(1073741824, 0),
    ?assertMatch({quota, #{bytes := 1073741824, flags := 0}}, Term),
    TermOver = nft_expr_ir:quota(524288000, 1),
    ?assertMatch({quota, #{bytes := 524288000, flags := 1}}, TermOver).

quota_ir_objref(_) ->
    Term = nft_expr_ir:objref_quota(<<"bandwidth">>),
    ?assertMatch({objref, #{type := quota, name := <<"bandwidth">>}}, Term).

quota_encode(_) ->
    Term = nft_expr_ir:quota(1000000, 0),
    Bin = nft_encode:expr(Term),
    {<<"quota">>, Attrs} = decode_expr(Bin),
    %% NFTA_QUOTA_BYTES = 1, should be u64
    ?assertMatch({1, <<1000000:64/big>>}, lists:keyfind(1, 1, Attrs)),
    %% NFTA_QUOTA_FLAGS = 2, should be u32
    ?assertMatch({2, <<0:32/big>>}, lists:keyfind(2, 1, Attrs)).

quota_object_encode(_) ->
    %% Verify nft_quota:add produces a binary message
    Msg = nft_quota:add(
        ?NFPROTO_INET,
        <<"fw">>,
        <<"bw">>,
        #{bytes => 1073741824, flags => 0},
        1
    ),
    ?assert(is_binary(Msg)),
    ?assert(byte_size(Msg) > 20),
    %% Should contain the quota name
    ?assertNotEqual(nomatch, binary:match(Msg, <<"bw">>)).

quota_rules_accept(_) ->
    Rule = nft_rules:quota_accept(80, tcp, #{bytes => 1000000, mode => until}),
    ?assert(is_list(Rule)),
    %% Should contain a quota expression
    ?assert(
        lists:any(
            fun
                ({quota, _}) -> true;
                (_) -> false
            end,
            Rule
        )
    ),
    %% Should end with accept
    ?assertMatch({immediate, #{verdict := accept}}, lists:last(Rule)).

quota_rules_drop(_) ->
    Rule = nft_rules:quota_drop(80, tcp, #{bytes => 500000, mode => over}),
    ?assert(is_list(Rule)),
    %% Should contain a quota expression with flags=1
    ?assert(
        lists:any(
            fun
                ({quota, #{flags := 1}}) -> true;
                (_) -> false
            end,
            Rule
        )
    ),
    %% Should end with drop
    ?assertMatch({immediate, #{verdict := drop}}, lists:last(Rule)).

%% --- Kernel tests ---

kernel_named_quota(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_quota:add(
                ?NFPROTO_INET,
                ?TABLE,
                <<"test_bw">>,
                #{bytes => 1073741824, flags => 0},
                Seq
            )
        end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    ?assertMatch([_], [Q || #{<<"quota">> := Q = #{<<"name">> := <<"test_bw">>}} <- Items]),
    [Quota] = [Q || #{<<"quota">> := Q = #{<<"name">> := <<"test_bw">>}} <- Items],
    ?assertEqual(1073741824, maps:get(<<"bytes">>, Quota)),
    nfnl_server:stop(Pid).

kernel_quota_in_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_quota:add(
                ?NFPROTO_INET,
                ?TABLE,
                <<"rule_bw">>,
                #{bytes => 524288000, flags => 0},
                Seq
            )
        end,
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
        nft_encode:rule_fun(
            inet,
            ?TABLE,
            ?CHAIN,
            [
                nft_expr_ir:meta(l4proto, 1),
                nft_expr_ir:cmp(eq, 1, <<6>>),
                nft_expr_ir:tcp_dport(1),
                nft_expr_ir:cmp(eq, 1, <<0, 80>>),
                nft_expr_ir:objref_quota(<<"rule_bw">>),
                nft_expr_ir:accept()
            ]
        )
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Quota object should exist
    ?assertMatch([_], [Q || #{<<"quota">> := Q = #{<<"name">> := <<"rule_bw">>}} <- Items]),
    %% Rule should exist and reference the quota
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assertMatch([_], Rules),
    [#{<<"expr">> := Exprs}] = Rules,
    %% nft JSON renders quota objref as {"quota": ...} not {"objref": ...}
    ExprJson = iolist_to_binary(json:encode(Exprs)),
    ?assert(binary:match(ExprJson, <<"quota">>) =/= nomatch),
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

decode_expr(Bin) ->
    Decoded = nfnl_attr:decode(Bin),
    {1, NameBin} = lists:keyfind(1, 1, Decoded),
    NameLen = byte_size(NameBin) - 1,
    <<Name:NameLen/binary, 0>> = NameBin,
    {2, nested, Attrs} = lists:keyfind(2, 1, Decoded),
    {Name, Attrs}.
