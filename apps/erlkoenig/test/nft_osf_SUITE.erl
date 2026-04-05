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

-module(nft_osf_SUITE).
-moduledoc """
OS fingerprinting (osf) expression tests for Erlkoenig.

Unit tests verify IR term construction and VM simulation.
Kernel tests verify the osf expression round-trips through Netlink
and appears correctly in `nft -j` output.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_osf">>).
-define(CHAIN, <<"input">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            osf_ir_term,
            osf_match_ir_term,
            osf_vm_loads_name,
            osf_vm_empty_default,
            osf_match_rule_accept,
            osf_match_rule_drop,
            osf_match_rule_mismatch,
            osf_encode_binary
        ]},
        {kernel, [], [
            kernel_osf_rule
        ]}
    ].

init_per_group(kernel, Config) ->
    case os:cmd("id -u") of
        "0\n" ->
            os:cmd("modprobe nft_osf 2>/dev/null"),
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

%% ===================================================================
%% Unit tests
%% ===================================================================

osf_ir_term(_) ->
    ?assertMatch({osf, #{dreg := 1}}, nft_expr_ir:osf(1)).

osf_match_ir_term(_) ->
    Exprs = nft_expr_ir:osf_match(1, <<"Linux">>),
    ?assertEqual(2, length(Exprs)),
    [{osf, #{dreg := 1}}, {cmp, #{sreg := 1, op := eq, data := <<"Linux">>}}] = Exprs.

osf_vm_loads_name(_) ->
    Pkt = nft_vm_pkt:raw(#{osf_name => <<"Linux">>}),
    {ok, R} = nft_vm:eval_expr({osf, #{dreg => 1}}, Pkt, nft_vm:new_regs()),
    ?assertEqual(<<"Linux">>, maps:get(1, maps:get(data, R))).

osf_vm_empty_default(_) ->
    %% When osf_name is not set, default to empty binary
    Pkt = nft_vm_pkt:raw(#{}),
    {ok, R} = nft_vm:eval_expr({osf, #{dreg => 1}}, Pkt, nft_vm:new_regs()),
    ?assertEqual(<<>>, maps:get(1, maps:get(data, R))).

osf_match_rule_accept(_) ->
    Pkt = nft_vm_pkt:raw(#{osf_name => <<"Linux">>}),
    Rule = nft_rules:osf_match(<<"Linux">>, accept),
    {accept, _, _} = nft_vm:eval_rule(Rule, Pkt, nft_vm:new_regs()).

osf_match_rule_drop(_) ->
    Pkt = nft_vm_pkt:raw(#{osf_name => <<"Windows">>}),
    Rule = nft_rules:osf_match(<<"Windows">>, drop),
    {drop, _, _} = nft_vm:eval_rule(Rule, Pkt, nft_vm:new_regs()).

osf_match_rule_mismatch(_) ->
    Pkt = nft_vm_pkt:raw(#{osf_name => <<"FreeBSD">>}),
    Rule = nft_rules:osf_match(<<"Linux">>, accept),
    {break, _, _} = nft_vm:eval_rule(Rule, Pkt, nft_vm:new_regs()).

osf_encode_binary(_) ->
    %% Verify that the osf IR term encodes to a non-empty binary
    Bin = nft_encode:expr(nft_expr_ir:osf(1)),
    ?assert(is_binary(Bin)),
    ?assert(byte_size(Bin) > 0).

%% ===================================================================
%% Kernel tests
%% ===================================================================

kernel_osf_rule(_Config) ->
    %% Create a table with a chain containing an osf + accept rule,
    %% then verify via `nft -j` that the osf expression is present.
    {ok, Pid} = nfnl_server:start_link(),
    OsfRule = [nft_expr_ir:osf(1), nft_expr_ir:accept()],
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
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, OsfRule)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Find rules in the JSON output
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assert(length(Rules) > 0),
    %% Verify that at least one rule contains an osf expression
    %% nft JSON may nest osf inside "match" objects; search recursively
    RulesJson = iolist_to_binary(json:encode(Rules)),
    ?assert(binary:match(RulesJson, <<"osf">>) =/= nomatch),
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
