-module(nft_delete_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-define(NFPROTO_INET, 1).
-define(TABLE, <<"erltest_del">>).
-define(CHAIN, <<"input">>).
-define(SET, <<"banned">>).

all() ->
    [{group, unit},
     {group, kernel}].

groups() ->
    [{unit, [parallel], [delete_table_msg, delete_chain_msg, delete_set_msg]},
     {kernel, [], [kernel_delete_table, kernel_delete_chain, kernel_delete_set]}].

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

delete_table_msg(_) ->
    Msg = nft_delete:table(1, <<"fw">>, 1),
    %% NFT_MSG_DELTABLE=2, type = (10 << 8) | 2 = 2562
    <<_:32, 2562:16/little, _/binary>> = Msg.

delete_chain_msg(_) ->
    Msg = nft_delete:chain(1, <<"fw">>, <<"input">>, 1),
    %% NFT_MSG_DELCHAIN=5, type = (10 << 8) | 5 = 2565
    <<_:32, 2565:16/little, _/binary>> = Msg,
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    ?assertMatch({1, <<"fw", 0>>}, lists:keyfind(1, 1, Decoded)),
    ?assertMatch({3, <<"input", 0>>}, lists:keyfind(3, 1, Decoded)).

delete_set_msg(_) ->
    Msg = nft_delete:set(1, <<"fw">>, <<"banned">>, 1),
    %% NFT_MSG_DELSET=11, type = (10 << 8) | 11 = 2571
    <<_:32, 2571:16/little, _/binary>> = Msg.

%% --- Kernel tests ---

kernel_delete_table(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end
    ]),
    %% Verify table exists
    Output1 = os:cmd("nft list tables"),
    ?assertNotEqual(nomatch, string:find(Output1, "erltest_del")),
    %% Delete it
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_delete:table(?NFPROTO_INET, ?TABLE, Seq) end
    ]),
    %% Verify it's gone
    Output2 = os:cmd("nft list tables"),
    ?assertEqual(nomatch, string:find(Output2, "erltest_del")),
    nfnl_server:stop(Pid).

kernel_delete_chain(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => ?CHAIN,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, Seq) end
    ]),
    %% Verify chain exists
    Output1 = os:cmd("nft list chain inet " ++ binary_to_list(?TABLE)
                      ++ " " ++ binary_to_list(?CHAIN)),
    ?assertNotEqual([], Output1),
    %% Delete chain
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_delete:chain(?NFPROTO_INET, ?TABLE, ?CHAIN, Seq) end
    ]),
    %% Verify table still exists but chain is gone
    Output2 = os:cmd("nft list table inet " ++ binary_to_list(?TABLE)),
    ?assertNotEqual([], Output2),
    Output3 = os:cmd("nft list chain inet " ++ binary_to_list(?TABLE)
                      ++ " " ++ binary_to_list(?CHAIN) ++ " 2>&1"),
    ?assertNotEqual(nomatch, string:find(Output3, "Error")),
    nfnl_server:stop(Pid).

kernel_delete_set(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_set:add(?NFPROTO_INET, #{
            table => ?TABLE, name => ?SET,
            type => ipv4_addr, id => 1
        }, Seq) end
    ]),
    %% Verify set exists
    Output1 = os:cmd("nft list sets inet " ++ binary_to_list(?TABLE)),
    ?assertNotEqual(nomatch, string:find(Output1, "banned")),
    %% Delete set
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_delete:set(?NFPROTO_INET, ?TABLE, ?SET, Seq) end
    ]),
    %% Verify table exists but set is gone
    Output2 = os:cmd("nft list table inet " ++ binary_to_list(?TABLE)),
    ?assertNotEqual([], Output2),
    Output3 = os:cmd("nft list sets inet " ++ binary_to_list(?TABLE)),
    ?assertEqual(nomatch, string:find(Output3, "banned")),
    nfnl_server:stop(Pid).
