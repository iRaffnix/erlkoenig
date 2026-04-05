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

-module(nft_dup_SUITE).
-moduledoc """
Packet duplication (TEE/dup) tests for Erlkoenig.

Unit tests verify IR construction and encoding. Kernel tests verify
that dup expressions are accepted by the kernel via nft -j.
""".

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_dup">>).
-define(CHAIN, <<"prerouting">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            dup_ir_term,
            dup_encode_binary,
            dup_rule_tcp,
            dup_rule_udp,
            dup_chain_continues,
            dup_chain_wrong_port_skips
        ]},
        {kernel, [], [kernel_dup_rule_accepted, kernel_dup_expr_in_json]}
    ].

init_per_group(kernel, Config) ->
    case os:cmd("id -u") of
        "0\n" ->
            %% Ensure dup kernel module is loaded
            case os:cmd("modprobe nft_dup_ipv4 2>&1") of
                [] -> Config;
                _ -> {skip, "nft_dup kernel module not available"}
            end;
        _ ->
            {skip, "kernel tests require root"}
    end;
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    os:cmd("nft delete table inet " ++ binary_to_list(?TABLE) ++ " 2>/dev/null"),
    os:cmd("nft delete table ip " ++ binary_to_list(?TABLE) ++ " 2>/dev/null"),
    Config.

end_per_testcase(_TC, _Config) ->
    os:cmd("nft delete table inet " ++ binary_to_list(?TABLE) ++ " 2>/dev/null"),
    os:cmd("nft delete table ip " ++ binary_to_list(?TABLE) ++ " 2>/dev/null"),
    ok.

%% ===================================================================
%% Unit tests
%% ===================================================================

dup_ir_term(_) ->
    %% nft_expr_ir:dup/2 returns {dup, #{sreg_addr, sreg_dev}}
    Term = nft_expr_ir:dup(1, 2),
    ?assertMatch({dup, #{sreg_addr := 1, sreg_dev := 2}}, Term).

dup_encode_binary(_) ->
    %% Encoding produces a non-empty binary containing "dup"
    Term = nft_expr_ir:dup(1, 2),
    Bin = nft_encode:expr(Term),
    ?assert(is_binary(Bin)),
    ?assert(byte_size(Bin) > 0),
    ?assertNotEqual(nomatch, binary:match(Bin, <<"dup">>)).

dup_rule_tcp(_) ->
    %% dup_to/4 for TCP returns a valid rule list
    Rule = nft_rules:dup_to(<<10, 0, 0, 2>>, 3, 443, tcp),
    ?assert(is_list(Rule)),
    ?assertEqual(7, length(Rule)),
    %% Last expr should be {dup, _}
    ?assertMatch({dup, _}, lists:last(Rule)).

dup_rule_udp(_) ->
    %% dup_to/4 for UDP returns a valid rule list
    Rule = nft_rules:dup_to(<<10, 0, 0, 2>>, 3, 53, udp),
    ?assert(is_list(Rule)),
    ?assertEqual(7, length(Rule)),
    ?assertMatch({dup, _}, lists:last(Rule)).

dup_chain_continues(_) ->
    %% Dup is a side-effect: the chain continues after the dup rule
    DupRule = nft_rules:dup_to(<<10, 0, 0, 2>>, 3, 443, tcp),
    AcceptRule = [nft_expr_ir:accept()],
    Pkt = nft_vm_pkt:tcp(#{saddr => {192, 168, 1, 1}}, #{dport => 443}),
    {accept, _} = nft_vm:eval_chain([DupRule, AcceptRule], Pkt).

dup_chain_wrong_port_skips(_) ->
    %% When port doesn't match, dup rule BREAKs and next rule fires
    DupRule = nft_rules:dup_to(<<10, 0, 0, 2>>, 3, 443, tcp),
    AcceptRule = [nft_expr_ir:accept()],
    Pkt = nft_vm_pkt:tcp(#{saddr => {192, 168, 1, 1}}, #{dport => 80}),
    %% Port 80 doesn't match dup_to for 443, so dup BREAKs
    %% Falls through to accept rule
    {accept, _} = nft_vm:eval_chain([DupRule, AcceptRule], Pkt).

%% ===================================================================
%% Kernel tests
%% ===================================================================

kernel_dup_rule_accepted(_Config) ->
    %% Verify the kernel accepts a rule containing a dup expression.
    %% dup expression is only registered for ip/ip6 families, not inet.
    {ok, Pid} = nfnl_server:start_link(),
    Rule = nft_rules:dup_to(<<10, 0, 0, 2>>, 3, 443, tcp),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_IPV4, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_IPV4,
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
        nft_encode:rule_fun(ip, ?TABLE, ?CHAIN, Rule)
    ]),
    Items = nft_json("list table ip " ++ binary_to_list(?TABLE)),
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assertMatch([_], Rules),
    nfnl_server:stop(Pid).

kernel_dup_expr_in_json(_Config) ->
    %% Verify the dup expression appears in nft -j output.
    %% dup expression is only registered for ip/ip6 families, not inet.
    {ok, Pid} = nfnl_server:start_link(),
    Rule = nft_rules:dup_to(<<10, 0, 0, 2>>, 3, 443, tcp),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_IPV4, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_IPV4,
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
        nft_encode:rule_fun(ip, ?TABLE, ?CHAIN, Rule)
    ]),
    Items = nft_json("list table ip " ++ binary_to_list(?TABLE)),
    [#{<<"expr">> := Exprs}] = [R || #{<<"rule">> := R} <- Items],
    %% There should be a dup expression in the rule
    DupExprs = [E || E <- Exprs, maps:is_key(<<"dup">>, E)],
    ?assertMatch([_], DupExprs),
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
