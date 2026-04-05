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

-module(nft_notrack_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_notrack">>).
-define(CHAIN, <<"raw_prerouting">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [notrack_ir, notrack_rule_udp, notrack_rule_tcp]},
        {kernel, [], [kernel_notrack_rule]}
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

notrack_ir(_) ->
    Expr = nft_expr_ir:notrack(),
    ?assertMatch({notrack, #{}}, Expr).

notrack_rule_udp(_) ->
    Rule = nft_rules:notrack_rule(53, udp),
    ?assert(is_list(Rule)),
    ?assert(
        lists:any(
            fun
                ({notrack, #{}}) -> true;
                (_) -> false
            end,
            Rule
        )
    ).

notrack_rule_tcp(_) ->
    Rule = nft_rules:notrack_rule(80, tcp),
    ?assert(is_list(Rule)),
    ?assert(
        lists:any(
            fun
                ({notrack, #{}}) -> true;
                (_) -> false
            end,
            Rule
        )
    ).

%% --- Kernel tests ---

kernel_notrack_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?CHAIN,
                    hook => prerouting,
                    type => filter,
                    priority => -300,
                    policy => accept
                },
                Seq
            )
        end,
        nft_encode:rule_fun(
            inet,
            ?TABLE,
            ?CHAIN,
            nft_rules:notrack_rule(53, udp)
        )
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Find rules in the JSON output
    RuleExprs = [
        Expr
     || #{
            <<"rule">> := #{
                <<"chain">> := ?CHAIN,
                <<"expr">> := Expr
            }
        } <- Items
    ],
    ?assertMatch([_ | _], RuleExprs),
    %% The first (and only) rule's expressions should contain a notrack
    [Exprs] = RuleExprs,
    HasNotrack = lists:any(
        fun
            (#{<<"notrack">> := null}) -> true;
            (_) -> false
        end,
        Exprs
    ),
    ?assert(HasNotrack),
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
