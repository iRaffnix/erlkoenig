-module(nft_log_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-define(NFPROTO_INET, 1).
-define(TABLE, <<"erltest_log">>).
-define(CHAIN, <<"input">>).

all() ->
    [{group, unit},
     {group, kernel}].

groups() ->
    [{unit, [parallel], [log_default, log_with_prefix, log_with_group,
                         log_with_level, log_full_opts, log_drop_rule,
                         log_drop_count_rule]},
     {kernel, [], [kernel_log_rule, kernel_log_with_prefix,
                   kernel_log_drop_rule]}].

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

log_default(_) ->
    Bin = nft_expr_log:new(),
    {<<"log">>, _Attrs} = decode_expr(Bin).

log_with_prefix(_) ->
    Bin = nft_expr_log:new(#{prefix => <<"DROP: ">>}),
    {<<"log">>, Attrs} = decode_expr(Bin),
    ?assertMatch({2, <<"DROP: ", 0>>}, lists:keyfind(2, 1, Attrs)).

log_with_group(_) ->
    Bin = nft_expr_log:new(#{group => 5}),
    {<<"log">>, Attrs} = decode_expr(Bin),
    ?assertMatch({1, <<5:16/big>>}, lists:keyfind(1, 1, Attrs)).

log_with_level(_) ->
    Bin = nft_expr_log:new(#{level => 3}),
    {<<"log">>, Attrs} = decode_expr(Bin),
    ?assertMatch({5, <<3:32/big>>}, lists:keyfind(5, 1, Attrs)).

log_full_opts(_) ->
    Bin = nft_expr_log:new(#{prefix => <<"FW: ">>, group => 1, snaplen => 128, level => 4}),
    {<<"log">>, Attrs} = decode_expr(Bin),
    ?assertMatch({1, <<1:16/big>>}, lists:keyfind(1, 1, Attrs)),
    ?assertMatch({2, <<"FW: ", 0>>}, lists:keyfind(2, 1, Attrs)),
    ?assertMatch({3, <<128:32/big>>}, lists:keyfind(3, 1, Attrs)),
    ?assertMatch({5, <<4:32/big>>}, lists:keyfind(5, 1, Attrs)).

log_drop_rule(_) ->
    Rule = nft_rules:log_drop(<<"BLOCKED: ">>),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"log">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"BLOCKED: ">>)).

log_drop_count_rule(_) ->
    Rule = nft_rules:log_drop_named(<<"DROP: ">>, <<"dropped">>),
    Fun = nft_encode:rule_fun(inet, <<"t">>, <<"c">>, Rule),
    Msg = Fun(1),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"objref">>)),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"log">>)).

%% --- Kernel tests ---

kernel_log_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    setup_table_and_chain(Pid),
    ok = nfnl_server:apply_msgs(Pid, [
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, [nft_expr_ir:log()])
    ]),
    Output = os:cmd("nft list chain inet " ++ binary_to_list(?TABLE)
                     ++ " " ++ binary_to_list(?CHAIN)),
    ?assertNotEqual(nomatch, string:find(Output, "log")),
    nfnl_server:stop(Pid).

kernel_log_with_prefix(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    setup_table_and_chain(Pid),
    ok = nfnl_server:apply_msgs(Pid, [
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN,
            [nft_expr_ir:log(#{prefix => <<"TEST: ">>})])
    ]),
    Output = os:cmd("nft list chain inet " ++ binary_to_list(?TABLE)
                     ++ " " ++ binary_to_list(?CHAIN)),
    ?assertNotEqual(nomatch, string:find(Output, "TEST:")),
    nfnl_server:stop(Pid).

kernel_log_drop_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    setup_table_and_chain(Pid),
    ok = nfnl_server:apply_msgs(Pid, [
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN,
            nft_rules:log_drop(<<"BLOCKED: ">>))
    ]),
    Output = os:cmd("nft list chain inet " ++ binary_to_list(?TABLE)
                     ++ " " ++ binary_to_list(?CHAIN)),
    ?assertNotEqual(nomatch, string:find(Output, "log")),
    ?assertNotEqual(nomatch, string:find(Output, "BLOCKED:")),
    ?assertNotEqual(nomatch, string:find(Output, "drop")),
    nfnl_server:stop(Pid).

%% --- Helpers ---

setup_table_and_chain(Pid) ->
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => ?CHAIN,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, Seq) end
    ]).

decode_expr(Bin) ->
    Decoded = nfnl_attr:decode(Bin),
    {1, NameBin} = lists:keyfind(1, 1, Decoded),
    NameLen = byte_size(NameBin) - 1,
    <<Name:NameLen/binary, 0>> = NameBin,
    {2, nested, Attrs} = lists:keyfind(2, 1, Decoded),
    {Name, Attrs}.
