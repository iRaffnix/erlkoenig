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

-module(nft_fib_SUITE).
-moduledoc """
FIB lookup expression tests for Erlkönig.

Unit tests verify IR construction and VM evaluation.
Kernel tests verify that FIB expressions encode correctly
and are accepted by nf_tables via `nft -j`.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_fib">>).
-define(CHAIN, <<"rpf">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            fib_ir_term,
            fib_rpf_ir_structure,
            fib_rpf_rule_builder,
            fib_vm_valid_path,
            fib_vm_invalid_path,
            fib_vm_default_zero,
            fib_chain_rpf_valid,
            fib_chain_rpf_spoofed
        ]},
        {kernel, [], [
            kernel_fib_rpf_rule
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
%% Unit tests
%% ===================================================================

fib_ir_term(_) ->
    %% fib/3 produces the expected IR tuple
    Expr = nft_expr_ir:fib(0, 9, 1),
    ?assertMatch({fib, #{result := 0, flags := 9, dreg := 1}}, Expr).

fib_rpf_ir_structure(_) ->
    %% fib_rpf/0 returns a 3-expression list: fib, cmp, drop
    Exprs = nft_expr_ir:fib_rpf(),
    ?assertEqual(3, length(Exprs)),
    [{fib, FibOpts}, {cmp, CmpOpts}, {immediate, ImmOpts}] = Exprs,
    %% FIB: saddr(1) | iif(8) = 9, result oif(1), dreg 1
    ?assertEqual(1, maps:get(result, FibOpts)),
    ?assertEqual(9, maps:get(flags, FibOpts)),
    ?assertEqual(1, maps:get(dreg, FibOpts)),
    %% CMP: eq reg1 to <<0:32>>
    ?assertEqual(eq, maps:get(op, CmpOpts)),
    ?assertEqual(1, maps:get(sreg, CmpOpts)),
    ?assertEqual(<<0:32>>, maps:get(data, CmpOpts)),
    %% Verdict: drop
    ?assertEqual(drop, maps:get(verdict, ImmOpts)).

fib_rpf_rule_builder(_) ->
    %% nft_rules:fib_rpf_drop/0 returns the same as nft_expr_ir:fib_rpf/0
    ?assertEqual(nft_expr_ir:fib_rpf(), nft_rules:fib_rpf_drop()).

fib_vm_valid_path(_) ->
    %% A single fib expression with fib_result=2 stores 2 in the register
    Pkt = #{fib_result => 2},
    {ok, Regs} = nft_vm:eval_expr(
        {fib, #{result => 0, flags => 9, dreg => 1}}, Pkt, nft_vm:new_regs()
    ),
    ?assertEqual(<<2:32/native>>, maps:get(1, maps:get(data, Regs))).

fib_vm_invalid_path(_) ->
    %% A single fib expression with fib_result=0 stores 0 in the register
    Pkt = #{fib_result => 0},
    {ok, Regs} = nft_vm:eval_expr(
        {fib, #{result => 0, flags => 9, dreg => 1}}, Pkt, nft_vm:new_regs()
    ),
    ?assertEqual(<<0:32/native>>, maps:get(1, maps:get(data, Regs))).

fib_vm_default_zero(_) ->
    %% When fib_result is not set, defaults to 0
    Pkt = nft_vm_pkt:raw(#{}),
    {ok, Regs} = nft_vm:eval_expr(
        {fib, #{result => 0, flags => 9, dreg => 1}}, Pkt, nft_vm:new_regs()
    ),
    ?assertEqual(<<0:32/native>>, maps:get(1, maps:get(data, Regs))).

fib_chain_rpf_valid(_) ->
    %% A chain with RPF + tcp_accept: valid RPF passes through to accept
    Rules = [
        nft_rules:fib_rpf_drop(),
        nft_rules:tcp_accept(80),
        nft_rules:log_drop(<<"DROP: ">>)
    ],
    Pkt = nft_vm_pkt:tcp(#{saddr => {10, 0, 0, 1}}, #{dport => 80}),
    PktOk = Pkt#{fib_result => 3},
    {accept, _} = nft_vm:eval_chain(Rules, PktOk).

fib_chain_rpf_spoofed(_) ->
    %% A chain with RPF: spoofed source (fib_result=0) gets dropped
    Rules = [
        nft_rules:fib_rpf_drop(),
        nft_rules:tcp_accept(80),
        nft_rules:log_drop(<<"DROP: ">>)
    ],
    Pkt = nft_vm_pkt:tcp(#{saddr => {10, 0, 0, 1}}, #{dport => 80}),
    PktSpoofed = Pkt#{fib_result => 0},
    {drop, _} = nft_vm:eval_chain(Rules, PktSpoofed).

%% ===================================================================
%% Kernel tests
%% ===================================================================

kernel_fib_rpf_rule(_Config) ->
    %% Create a table + chain + RPF rule, then verify via nft -j
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
                    priority => 0,
                    policy => accept
                },
                Seq
            )
        end,
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, nft_rules:fib_rpf_drop())
    ]),
    %% Query the ruleset as JSON
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Find rules
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assert(length(Rules) > 0),
    %% The rule should contain a fib expression
    %% nft JSON nests fib inside 'match' objects; search recursively
    RulesJson = iolist_to_binary(json:encode(Rules)),
    ?assert(binary:match(RulesJson, <<"fib">>) =/= nomatch),
    ?assert(binary:match(RulesJson, <<"oif">>) =/= nomatch),
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
