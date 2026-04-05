-module(nft_counter_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_cnt">>).
-define(CHAIN, <<"input">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            counter_new_zero,
            counter_new_values,
            counter_expr_name,
            counter_in_tcp_accept,
            counter_in_lookup_drop
        ]},
        {kernel, [], [
            kernel_named_counter,
            kernel_counter_in_rule,
            kernel_counter_values
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

counter_new_zero(_) ->
    Bin = nft_expr_counter:new(),
    {<<"counter">>, Attrs} = decode_expr(Bin),
    ?assertMatch({1, <<0:64/big>>}, lists:keyfind(1, 1, Attrs)),
    ?assertMatch({2, <<0:64/big>>}, lists:keyfind(2, 1, Attrs)).

counter_new_values(_) ->
    Bin = nft_expr_counter:new(100, 5000),
    {<<"counter">>, Attrs} = decode_expr(Bin),
    ?assertMatch({1, <<5000:64/big>>}, lists:keyfind(1, 1, Attrs)),
    ?assertMatch({2, <<100:64/big>>}, lists:keyfind(2, 1, Attrs)).

counter_expr_name(_) ->
    Bin = nft_expr_counter:new(),
    Decoded = nfnl_attr:decode(Bin),
    ?assertMatch({1, <<"counter", 0>>}, lists:keyfind(1, 1, Decoded)).

counter_in_tcp_accept(_) ->
    Rule = nft_rules:tcp_accept_named(80, <<"http">>),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    {4, nested, Exprs} = lists:keyfind(4, 1, Decoded),
    %% Should have 6 expressions: meta, cmp, payload, cmp, objref, immediate
    ?assertEqual(6, length(Exprs)),
    %% 5th should be objref (named counter reference)
    {1, nested, ObjOuter} = lists:nth(5, Exprs),
    ?assertMatch({1, <<"objref", 0>>}, lists:keyfind(1, 1, ObjOuter)).

counter_in_lookup_drop(_) ->
    Rule = nft_rules:set_lookup_drop_named(<<"banned">>, <<"banned">>),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    ?assert(byte_size(Msg) > 20),
    %% Should contain "objref" expression name (named counter)
    ?assertNotEqual(nomatch, binary:match(Msg, <<"objref">>)).

%% --- Kernel tests ---

kernel_named_counter(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_object:add_counter(?NFPROTO_INET, ?TABLE, <<"test_cnt">>, Seq) end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    ?assertMatch([_], [C || #{<<"counter">> := C = #{<<"name">> := <<"test_cnt">>}} <- Items]),
    nfnl_server:stop(Pid).

kernel_counter_in_rule(_Config) ->
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
                nft_expr_ir:counter(),
                nft_expr_ir:accept()
            ]
        )
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assertMatch([_], Rules),
    [#{<<"expr">> := Exprs}] = Rules,
    ?assert(lists:any(fun(E) -> maps:is_key(<<"counter">>, E) end, Exprs)),
    nfnl_server:stop(Pid).

kernel_counter_values(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_object:add_counter(?NFPROTO_INET, ?TABLE, <<"val_cnt">>, Seq) end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    [Counter] = [C || #{<<"counter">> := C = #{<<"name">> := <<"val_cnt">>}} <- Items],
    ?assertEqual(0, maps:get(<<"packets">>, Counter)),
    ?assertEqual(0, maps:get(<<"bytes">>, Counter)),
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
