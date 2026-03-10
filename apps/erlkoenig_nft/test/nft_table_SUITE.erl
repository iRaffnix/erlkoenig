-module(nft_table_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-define(NFPROTO_INET, 1).
-define(TABLE, <<"erltest_tbl">>).

all() ->
    [{group, unit},
     {group, kernel}].

groups() ->
    [{unit, [parallel], [add_inet_table, add_ipv4_table, table_attrs_decodable]},
     {kernel, [], [kernel_create_inet_table, kernel_create_ipv4_table,
                   kernel_table_idempotent]}].

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
    os:cmd("nft delete table ip " ++ binary_to_list(?TABLE) ++ " 2>/dev/null"),
    Config.

end_per_testcase(_TC, _Config) ->
    os:cmd("nft delete table inet " ++ binary_to_list(?TABLE) ++ " 2>/dev/null"),
    os:cmd("nft delete table ip " ++ binary_to_list(?TABLE) ++ " 2>/dev/null"),
    ok.

%% --- Unit tests ---

add_inet_table(_) ->
    Msg = nft_table:add(1, <<"test">>, 100),
    %% Should be a valid nlmsg with type NEWTABLE
    <<_Len:32/little, 2560:16/little, _Flags:16/little,
      100:32/little, _:32, _/binary>> = Msg.

add_ipv4_table(_) ->
    Msg = nft_table:add(2, <<"fw">>, 1),
    <<_:32, 2560:16/little, _:16, 1:32/little, _:32,
      2:8, _/binary>> = Msg.  %% Family=2 in nfgenmsg

table_attrs_decodable(_) ->
    Msg = nft_table:add(1, <<"mytable">>, 50),
    %% Skip nlmsghdr(16) + nfgenmsg(4) = 20 bytes to get attrs
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    ?assertMatch([{1, <<"mytable", 0>>}, {2, <<0:32>>}], Decoded).

%% --- Kernel tests ---

kernel_create_inet_table(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end
    ]),
    Output = os:cmd("nft list table inet " ++ binary_to_list(?TABLE)),
    ?assertNotEqual([], Output),
    ?assertNotEqual(nomatch, string:find(Output, "erltest_tbl")),
    nfnl_server:stop(Pid).

kernel_create_ipv4_table(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(2, ?TABLE, Seq) end
    ]),
    Output = os:cmd("nft list table ip " ++ binary_to_list(?TABLE)),
    ?assertNotEqual([], Output),
    ?assertNotEqual(nomatch, string:find(Output, "erltest_tbl")),
    nfnl_server:stop(Pid).

kernel_table_idempotent(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end
    ]),
    Result = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end
    ]),
    ?assertEqual(ok, Result),
    nfnl_server:stop(Pid).
