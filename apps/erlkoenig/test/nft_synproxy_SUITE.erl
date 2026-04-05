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

-module(nft_synproxy_SUITE).
-moduledoc """
SYN proxy tests for Erlkönig.

Unit tests verify IR construction, rule builder output, and VM evaluation.
Kernel tests verify that synproxy expressions encode correctly
and are accepted by nf_tables via `nft -j`.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_synproxy">>).
-define(RAW_CHAIN, <<"raw_pre">>).
-define(FILTER_CHAIN, <<"input">>).
-define(TCP, 6).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            synproxy_ir_term,
            synproxy_filter_rule_structure,
            synproxy_rules_returns_two_lists,
            synproxy_flags_timestamp_sack,
            synproxy_vm_terminal_verdict,
            synproxy_vm_wrong_port_breaks,
            synproxy_vm_chain_untracked_syn
        ]},
        {kernel, [], [
            kernel_synproxy_rules
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

synproxy_ir_term(_) ->
    %% synproxy/3 produces the expected IR tuple
    Expr = nft_expr_ir:synproxy(1460, 7, 3),
    ?assertMatch({synproxy, #{mss := 1460, wscale := 7, flags := 3}}, Expr).

synproxy_filter_rule_structure(_) ->
    %% synproxy_filter_rule returns a list starting with ct state check
    %% and ending with synproxy expression
    Rule = nft_expr_ir:synproxy_filter_rule(80, #{mss => 1460, wscale => 7}),
    ?assert(is_list(Rule)),
    ?assert(length(Rule) >= 4),
    %% First expression is ct state load
    {ct, #{key := state}} = hd(Rule),
    %% Last expression is synproxy
    {synproxy, #{mss := 1460, wscale := 7}} = lists:last(Rule).

synproxy_rules_returns_two_lists(_) ->
    %% synproxy_rules/2 returns {NotrackRules, FilterRules}
    {Notrack, Filter} = nft_rules:synproxy_rules(
        [80, 443],
        #{mss => 1460, wscale => 7}
    ),
    ?assertEqual(2, length(Notrack)),
    ?assertEqual(2, length(Filter)),
    %% Each notrack rule ends with notrack expression
    lists:foreach(
        fun(R) ->
            {notrack, #{}} = lists:last(R)
        end,
        Notrack
    ),
    %% Each filter rule ends with synproxy expression
    lists:foreach(
        fun(R) ->
            {synproxy, _} = lists:last(R)
        end,
        Filter
    ).

synproxy_flags_timestamp_sack(_) ->
    %% timestamp=true, sack_perm=true should set flags=3
    Rule = nft_expr_ir:synproxy_filter_rule(
        80,
        #{mss => 1460, wscale => 7, timestamp => true, sack_perm => true}
    ),
    {synproxy, #{flags := Flags}} = lists:last(Rule),
    ?assertEqual(3, Flags),
    %% timestamp only = 1
    Rule2 = nft_expr_ir:synproxy_filter_rule(
        80,
        #{mss => 1460, wscale => 7, timestamp => true}
    ),
    {synproxy, #{flags := 1}} = lists:last(Rule2),
    %% sack_perm only = 2
    Rule3 = nft_expr_ir:synproxy_filter_rule(
        80,
        #{mss => 1460, wscale => 7, sack_perm => true}
    ),
    {synproxy, #{flags := 2}} = lists:last(Rule3).

synproxy_vm_terminal_verdict(_) ->
    %% synproxy expression is terminal in the VM (like queue)
    Expr = nft_expr_ir:synproxy(1460, 7, 3),
    Regs = nft_vm:new_regs(),
    Result = nft_vm:eval_expr(Expr, #{}, Regs),
    ?assertMatch({{verdict, {synproxy, #{mss := 1460}}}, _}, Result).

synproxy_vm_wrong_port_breaks(_) ->
    %% A synproxy filter rule for port 80 should break on port 443
    Rule = nft_rules:synproxy_filter_rule(80, #{mss => 1460, wscale => 7}),
    %% Packet with TCP dport 443, ct_state untracked
    Pkt = nft_vm_pkt:tcp(
        #{saddr => {10, 0, 0, 1}},
        #{dport => 443},
        #{ct_state => untracked}
    ),
    {break, _, _} = nft_vm:eval_rule(Rule, Pkt, nft_vm:new_regs()).

synproxy_vm_chain_untracked_syn(_) ->
    %% A synproxy filter rule for port 80 should match untracked TCP to port 80
    Rule = nft_rules:synproxy_filter_rule(80, #{mss => 1460, wscale => 7}),
    Pkt = nft_vm_pkt:tcp(
        #{saddr => {10, 0, 0, 1}},
        #{dport => 80},
        #{ct_state => untracked}
    ),
    {{synproxy, _}, _} = nft_vm:eval_chain([Rule], Pkt, drop).

%% ===================================================================
%% Kernel tests
%% ===================================================================

kernel_synproxy_rules(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    %% Build synproxy rules for port 80
    {[NotrackRule], [FilterRule]} = nft_rules:synproxy_rules(
        [80],
        #{mss => 1460, wscale => 7, timestamp => true, sack_perm => true}
    ),

    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        %% Raw chain for notrack (priority -300)
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?RAW_CHAIN,
                    hook => prerouting,
                    type => filter,
                    priority => -300,
                    policy => accept
                },
                Seq
            )
        end,
        %% Filter chain
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?FILTER_CHAIN,
                    hook => input,
                    type => filter,
                    priority => 0,
                    policy => drop
                },
                Seq
            )
        end,
        %% Notrack rule in raw chain
        nft_encode:rule_fun(?NFPROTO_INET, ?TABLE, ?RAW_CHAIN, NotrackRule),
        %% Synproxy rule in filter chain
        nft_encode:rule_fun(?NFPROTO_INET, ?TABLE, ?FILTER_CHAIN, FilterRule)
    ]),

    %% Verify via nft -j
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),

    %% Check notrack expression in raw chain
    RawRules = rules_for_chain(Items, ?RAW_CHAIN),
    ?assert(length(RawRules) >= 1),
    ?assert(lists:any(fun has_notrack_expr/1, RawRules)),

    %% Check synproxy expression in filter chain
    FilterRules = rules_for_chain(Items, ?FILTER_CHAIN),
    ?assert(length(FilterRules) >= 1),
    ?assert(lists:any(fun has_synproxy_expr/1, FilterRules)),

    nfnl_server:stop(Pid).

%% ===================================================================
%% Helpers
%% ===================================================================

nft_json(Cmd) ->
    Output = os:cmd("nft -j " ++ Cmd),
    #{<<"nftables">> := Items} = json:decode(list_to_binary(Output)),
    Items.

rules_for_chain(Items, ChainName) ->
    [
        Rule
     || #{<<"rule">> := Rule = #{<<"chain">> := C}} <- Items,
        C =:= ChainName
    ].

has_notrack_expr(#{<<"expr">> := Exprs}) ->
    lists:any(
        fun
            (#{<<"notrack">> := _}) -> true;
            (_) -> false
        end,
        Exprs
    );
has_notrack_expr(_) ->
    false.

has_synproxy_expr(#{<<"expr">> := Exprs}) ->
    lists:any(
        fun
            (#{<<"synproxy">> := _}) -> true;
            (_) -> false
        end,
        Exprs
    );
has_synproxy_expr(_) ->
    false.
