-module(nft_set_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-define(NFPROTO_INET, 1).
-define(TABLE, <<"erltest_set">>).
-define(CHAIN, <<"input">>).
-define(SET, <<"banned">>).

all() ->
    [{group, unit},
     {group, kernel}].

groups() ->
    [{unit, [parallel], [set_add_ipv4, set_add_with_timeout, set_attrs_decodable,
                         elem_add_key, elem_add_with_timeout, elem_del_key,
                         lookup_match, lookup_not_match]},
     {kernel, [], [kernel_create_set, kernel_set_with_timeout,
                   kernel_add_elem, kernel_del_elem, kernel_set_lookup_rule]}].

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

set_add_ipv4(_) ->
    Msg = nft_set:add(1, #{
        table => <<"fw">>, name => <<"banned">>,
        type => ipv4_addr, id => 1
    }, 100),
    %% NFT_MSG_NEWSET = 9, type = (10 << 8) | 9 = 2569
    <<_Len:32/little, 2569:16/little, _/binary>> = Msg.

set_add_with_timeout(_) ->
    Msg = nft_set:add(1, #{
        table => <<"fw">>, name => <<"banned">>,
        type => ipv4_addr, flags => [timeout],
        timeout => 3600000, id => 1
    }, 100),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    %% NFTA_SET_FLAGS(3) should have timeout bit (0x10)
    {3, <<Flags:32/big>>} = lists:keyfind(3, 1, Decoded),
    ?assertEqual(16#10, Flags band 16#10),
    %% NFTA_SET_TIMEOUT(17) should be present
    ?assertMatch({11, <<3600000:64/big>>}, lists:keyfind(11, 1, Decoded)).

set_attrs_decodable(_) ->
    Msg = nft_set:add(1, #{
        table => <<"fw">>, name => <<"banned">>,
        type => ipv4_addr, id => 42
    }, 1),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    ?assertMatch({1, <<"fw", 0>>}, lists:keyfind(1, 1, Decoded)),
    ?assertMatch({2, <<"banned", 0>>}, lists:keyfind(2, 1, Decoded)),
    %% KEY_TYPE(4) = 7 (ipv4_addr)
    ?assertMatch({4, <<7:32/big>>}, lists:keyfind(4, 1, Decoded)),
    %% KEY_LEN(5) = 4
    ?assertMatch({5, <<4:32/big>>}, lists:keyfind(5, 1, Decoded)),
    %% SET_ID(16) = 42
    ?assertMatch({10, <<42:32/big>>}, lists:keyfind(10, 1, Decoded)).

elem_add_key(_) ->
    Msg = nft_set_elem:add(1, <<"fw">>, <<"banned">>, <<10, 0, 0, 5>>, 1),
    %% NFT_MSG_NEWSETELEM = 12, type = (10 << 8) | 12 = 2572
    <<_Len:32/little, 2572:16/little, _/binary>> = Msg.

elem_add_with_timeout(_) ->
    Msg = nft_set_elem:add(1, <<"fw">>, <<"banned">>, <<10, 0, 0, 5>>, 60000, 1),
    ?assert(byte_size(Msg) > 20),
    %% Should contain the timeout value
    ?assertNotEqual(nomatch, binary:match(Msg, <<60000:64/big>>)).

elem_del_key(_) ->
    Msg = nft_set_elem:del(1, <<"fw">>, <<"banned">>, <<10, 0, 0, 5>>, 1),
    %% NFT_MSG_DELSETELEM = 14, type = (10 << 8) | 14 = 2574
    <<_Len:32/little, 2574:16/little, _/binary>> = Msg.

lookup_match(_) ->
    Bin = nft_expr_lookup:match(1, <<"banned">>, 1),
    Decoded = nfnl_attr:decode(Bin),
    {1, <<"lookup", 0>>} = lists:keyfind(1, 1, Decoded).

lookup_not_match(_) ->
    Bin = nft_expr_lookup:not_match(1, <<"banned">>, 1),
    Decoded = nfnl_attr:decode(Bin),
    {2, nested, Inner} = lists:keyfind(2, 1, Decoded),
    %% Should have NFTA_LOOKUP_FLAGS(5) = 1 (INV)
    ?assertMatch({5, <<1:32/big>>}, lists:keyfind(5, 1, Inner)).

%% --- Kernel tests ---

kernel_create_set(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    setup_table_and_set(Pid),
    Output = os:cmd("nft list sets inet " ++ binary_to_list(?TABLE)),
    ?assertNotEqual(nomatch, string:find(Output, "banned")),
    nfnl_server:stop(Pid).

kernel_set_with_timeout(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_set:add(?NFPROTO_INET, #{
            table => ?TABLE, name => ?SET,
            type => ipv4_addr, flags => [timeout],
            timeout => 300000, id => 1
        }, Seq) end
    ]),
    Output = os:cmd("nft list sets inet " ++ binary_to_list(?TABLE)),
    ?assertNotEqual(nomatch, string:find(Output, "timeout")),
    nfnl_server:stop(Pid).

kernel_add_elem(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    setup_table_and_set(Pid),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_set_elem:add(?NFPROTO_INET, ?TABLE, ?SET, <<10,0,0,5>>, Seq) end
    ]),
    Output = os:cmd("nft list set inet " ++ binary_to_list(?TABLE) ++ " " ++ binary_to_list(?SET)),
    ?assertNotEqual(nomatch, string:find(Output, "10.0.0.5")),
    nfnl_server:stop(Pid).

kernel_del_elem(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    setup_table_and_set(Pid),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_set_elem:add(?NFPROTO_INET, ?TABLE, ?SET, <<10,0,0,5>>, Seq) end
    ]),
    %% Verify it's there
    Output1 = os:cmd("nft list set inet " ++ binary_to_list(?TABLE) ++ " " ++ binary_to_list(?SET)),
    ?assertNotEqual(nomatch, string:find(Output1, "10.0.0.5")),
    %% Delete it
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_set_elem:del(?NFPROTO_INET, ?TABLE, ?SET, <<10,0,0,5>>, Seq) end
    ]),
    %% Verify it's gone
    Output2 = os:cmd("nft list set inet " ++ binary_to_list(?TABLE) ++ " " ++ binary_to_list(?SET)),
    ?assertEqual(nomatch, string:find(Output2, "10.0.0.5")),
    nfnl_server:stop(Pid).

kernel_set_lookup_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    setup_table_and_set(Pid),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => ?TABLE, name => ?CHAIN,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, Seq) end,
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, nft_rules:set_lookup_drop(?SET))
    ]),
    Output = os:cmd("nft list chain inet " ++ binary_to_list(?TABLE) ++ " " ++ binary_to_list(?CHAIN)),
    ?assertNotEqual(nomatch, string:find(Output, "banned")),
    nfnl_server:stop(Pid).

%% --- Helpers ---

setup_table_and_set(Pid) ->
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) -> nft_set:add(?NFPROTO_INET, #{
            table => ?TABLE, name => ?SET,
            type => ipv4_addr, id => 1
        }, Seq) end
    ]).
