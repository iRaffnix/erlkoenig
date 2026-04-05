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

-module(nft_cgroup_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_cg">>).
-define(CHAIN, <<"input">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            ir_socket_cgroup,
            ir_socket_cgroup_encode,
            cgroup_accept_rule,
            cgroup_drop_rule
        ]},
        {kernel, [], [kernel_cgroup_rule]}
    ].

init_per_group(kernel, Config) ->
    case os:cmd("id -u") of
        "0\n" ->
            os:cmd("modprobe nft_socket 2>/dev/null"),
            Config;
        _ ->
            {skip, "kernel tests require root"}
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

ir_socket_cgroup(_) ->
    Term = nft_expr_ir:socket_cgroup(2),
    ?assertMatch({socket, #{key := cgroupv2, level := 2, dreg := 1}}, Term).

ir_socket_cgroup_encode(_) ->
    Term = nft_expr_ir:socket_cgroup(2),
    {<<"socket">>, Attrs} = decode_expr(nft_encode:expr(Term)),
    %% key = 3 (cgroupv2)
    ?assertMatch({1, <<3:32/big>>}, lists:keyfind(1, 1, Attrs)),
    %% dreg = 1
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)),
    %% level = 2
    ?assertMatch({3, <<2:32/big>>}, lists:keyfind(3, 1, Attrs)).

cgroup_accept_rule(_) ->
    Rule = nft_rules:cgroup_accept(42),
    ?assertMatch([{socket, #{key := cgroupv2}}, {cmp, _}, {immediate, #{verdict := accept}}], Rule).

cgroup_drop_rule(_) ->
    Rule = nft_rules:cgroup_drop(42),
    ?assertMatch([{socket, #{key := cgroupv2}}, {cmp, _}, {immediate, #{verdict := drop}}], Rule).

%% --- Kernel tests ---

kernel_cgroup_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    setup_table_and_chain(Pid),
    ok = nfnl_server:apply_msgs(Pid, [
        nft_encode:rule_fun(
            inet,
            ?TABLE,
            ?CHAIN,
            nft_rules:cgroup_accept(1)
        )
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assertMatch([_], Rules),
    [#{<<"expr">> := Exprs}] = Rules,
    %% nft JSON nests socket expressions inside "match" objects
    ExprJson = iolist_to_binary(json:encode(Exprs)),
    ?assert(binary:match(ExprJson, <<"socket">>) =/= nomatch),
    ?assert(binary:match(ExprJson, <<"cgroupv2">>) =/= nomatch),
    nfnl_server:stop(Pid).

%% --- Helpers ---

setup_table_and_chain(Pid) ->
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
        end
    ]).

decode_expr(Bin) ->
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
