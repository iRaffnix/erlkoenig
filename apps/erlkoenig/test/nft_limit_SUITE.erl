-module(nft_limit_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_lmt">>).
-define(CHAIN, <<"input">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            limit_pps,
            limit_bps,
            limit_over_pps,
            limit_over_bps,
            limit_custom_unit,
            limit_expr_name,
            limit_attrs_correct,
            limit_inv_flag,
            delete_rule_msg,
            delete_rule_has_handle
        ]},
        {kernel, [], [kernel_limit_in_rule, kernel_delete_rule]}
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

%% --- Limit expression ---

limit_pps(_) ->
    Bin = nft_expr_limit:pps(25, 5),
    {<<"limit">>, Attrs} = decode_expr(Bin),
    %% NFTA_LIMIT_RATE(1) = 25
    ?assertMatch({1, <<25:64/big>>}, lists:keyfind(1, 1, Attrs)),
    %% NFTA_LIMIT_UNIT(2) = 1 (per second)
    ?assertMatch({2, <<1:64/big>>}, lists:keyfind(2, 1, Attrs)),
    %% NFTA_LIMIT_BURST(3) = 5
    ?assertMatch({3, <<5:32/big>>}, lists:keyfind(3, 1, Attrs)),
    %% NFTA_LIMIT_TYPE(4) = 0 (pkts)
    ?assertMatch({4, <<0:32/big>>}, lists:keyfind(4, 1, Attrs)),
    %% NFTA_LIMIT_FLAGS(5) = 0 (not inverted)
    ?assertMatch({5, <<0:32/big>>}, lists:keyfind(5, 1, Attrs)).

limit_bps(_) ->
    Bin = nft_expr_limit:bps(10240, 1024),
    {<<"limit">>, Attrs} = decode_expr(Bin),
    ?assertMatch({1, <<10240:64/big>>}, lists:keyfind(1, 1, Attrs)),
    %% NFTA_LIMIT_TYPE(4) = 1 (bytes)
    ?assertMatch({4, <<1:32/big>>}, lists:keyfind(4, 1, Attrs)).

limit_over_pps(_) ->
    Bin = nft_expr_limit:over_pps(100, 10),
    {<<"limit">>, Attrs} = decode_expr(Bin),
    ?assertMatch({1, <<100:64/big>>}, lists:keyfind(1, 1, Attrs)),
    %% NFTA_LIMIT_FLAGS(5) = 1 (NFT_LIMIT_F_INV)
    ?assertMatch({5, <<1:32/big>>}, lists:keyfind(5, 1, Attrs)).

limit_over_bps(_) ->
    Bin = nft_expr_limit:over_bps(51200, 4096),
    {<<"limit">>, Attrs} = decode_expr(Bin),
    ?assertMatch({4, <<1:32/big>>}, lists:keyfind(4, 1, Attrs)),
    ?assertMatch({5, <<1:32/big>>}, lists:keyfind(5, 1, Attrs)).

limit_custom_unit(_) ->
    %% 50 packets per minute
    Bin = nft_expr_limit:new(#{rate => 50, unit => 60, burst => 10, type => pkts}),
    {<<"limit">>, Attrs} = decode_expr(Bin),
    ?assertMatch({1, <<50:64/big>>}, lists:keyfind(1, 1, Attrs)),
    ?assertMatch({2, <<60:64/big>>}, lists:keyfind(2, 1, Attrs)),
    ?assertMatch({3, <<10:32/big>>}, lists:keyfind(3, 1, Attrs)).

limit_expr_name(_) ->
    Bin = nft_expr_limit:pps(10, 5),
    Decoded = nfnl_attr:decode(Bin),
    ?assertMatch({1, <<"limit", 0>>}, lists:keyfind(1, 1, Decoded)).

limit_attrs_correct(_) ->
    %% Verify all 5 attributes are present
    Bin = nft_expr_limit:pps(1, 0),
    {<<"limit">>, Attrs} = decode_expr(Bin),
    ?assertEqual(5, length(Attrs)).

limit_inv_flag(_) ->
    %% Normal: flags = 0
    Bin1 = nft_expr_limit:pps(10, 5),
    {<<"limit">>, A1} = decode_expr(Bin1),
    ?assertMatch({5, <<0:32/big>>}, lists:keyfind(5, 1, A1)),
    %% Inverted: flags = 1
    Bin2 = nft_expr_limit:over_pps(10, 5),
    {<<"limit">>, A2} = decode_expr(Bin2),
    ?assertMatch({5, <<1:32/big>>}, lists:keyfind(5, 1, A2)).

%% --- Rule delete ---

delete_rule_msg(_) ->
    Msg = nft_delete:rule(1, <<"fw">>, <<"input">>, 42, 1),
    %% NFT_MSG_DELRULE=8, type = (10 << 8) | 8 = 2568
    <<_:32, 2568:16/little, _/binary>> = Msg.

delete_rule_has_handle(_) ->
    Msg = nft_delete:rule(1, <<"fw">>, <<"input">>, 99, 1),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    ?assertMatch({1, <<"fw", 0>>}, lists:keyfind(1, 1, Decoded)),
    ?assertMatch({2, <<"input", 0>>}, lists:keyfind(2, 1, Decoded)),
    %% NFTA_RULE_HANDLE(3) = 99 as u64/big
    ?assertMatch({3, <<99:64/big>>}, lists:keyfind(3, 1, Decoded)).

%% --- Kernel tests ---

kernel_limit_in_rule(_Config) ->
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
        nft_encode:rule_fun(
            inet,
            ?TABLE,
            ?CHAIN,
            [
                nft_expr_ir:meta(l4proto, 1),
                nft_expr_ir:cmp(eq, 1, <<6>>),
                nft_expr_ir:tcp_dport(1),
                nft_expr_ir:cmp(eq, 1, <<0, 80>>),
                nft_expr_ir:limit(25, 5),
                nft_expr_ir:accept()
            ]
        )
    ]),
    Output = os:cmd(
        "nft list chain inet " ++ binary_to_list(?TABLE) ++
            " " ++ binary_to_list(?CHAIN)
    ),
    ?assertNotEqual(nomatch, string:find(Output, "limit rate")),
    nfnl_server:stop(Pid).

kernel_delete_rule(_Config) ->
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
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, nft_rules:tcp_accept(80))
    ]),
    %% Verify rule exists
    Output1 = os:cmd(
        "nft list chain inet " ++ binary_to_list(?TABLE) ++
            " " ++ binary_to_list(?CHAIN)
    ),
    ?assertNotEqual(nomatch, string:find(Output1, "tcp dport 80")),
    %% Get the rule handle
    HandleOutput = os:cmd(
        "nft -a list chain inet " ++ binary_to_list(?TABLE) ++
            " " ++ binary_to_list(?CHAIN)
    ),
    Handle = extract_rule_handle(HandleOutput),
    ?assert(Handle > 0),
    %% Delete by handle
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_delete:rule(?NFPROTO_INET, ?TABLE, ?CHAIN, Handle, Seq) end
    ]),
    %% Verify rule is gone
    Output2 = os:cmd(
        "nft list chain inet " ++ binary_to_list(?TABLE) ++
            " " ++ binary_to_list(?CHAIN)
    ),
    ?assertEqual(nomatch, string:find(Output2, "tcp dport 80")),
    nfnl_server:stop(Pid).

%% --- Helpers ---

decode_expr(Bin) ->
    Decoded = nfnl_attr:decode(Bin),
    {1, NameBin} = lists:keyfind(1, 1, Decoded),
    NameLen = byte_size(NameBin) - 1,
    <<Name:NameLen/binary, 0>> = NameBin,
    {2, nested, Attrs} = lists:keyfind(2, 1, Decoded),
    {Name, Attrs}.

extract_rule_handle(Output) ->
    Lines = string:split(Output, "\n", all),
    RuleLines = [
        L
     || L <- Lines,
        string:find(L, "handle") =/= nomatch,
        string:find(L, "chain") =:= nomatch
    ],
    case RuleLines of
        [RuleLine | _] ->
            case re:run(RuleLine, "handle ([0-9]+)", [{capture, [1], list}]) of
                {match, [NumStr]} -> list_to_integer(NumStr);
                _ -> 0
            end;
        [] ->
            0
    end.
