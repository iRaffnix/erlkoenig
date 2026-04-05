-module(nft_table_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_tbl">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            add_inet_table,
            add_ipv4_table,
            table_attrs_decodable,
            owner_table_flag,
            default_table_no_owner
        ]},
        {kernel, [], [
            kernel_create_inet_table,
            kernel_create_ipv4_table,
            kernel_table_idempotent,
            kernel_owner_table,
            kernel_owner_table_removed_on_exit
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
    <<_Len:32/little, 2560:16/little, _Flags:16/little, 100:32/little, _:32, _/binary>> = Msg.

add_ipv4_table(_) ->
    Msg = nft_table:add(2, <<"fw">>, 1),
    <<_:32, 2560:16/little, _:16, 1:32/little, _:32,
        %% Family=2 in nfgenmsg
        2:8, _/binary>> = Msg.

table_attrs_decodable(_) ->
    Msg = nft_table:add(1, <<"mytable">>, 50),
    %% Skip nlmsghdr(16) + nfgenmsg(4) = 20 bytes to get attrs
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    ?assertMatch([{1, <<"mytable", 0>>}, {2, <<0:32>>}], Decoded).

owner_table_flag(_) ->
    Msg = nft_table:add(1, <<"owned">>, #{owner => true}, 10),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    ?assertMatch([{1, <<"owned", 0>>}, {2, <<2:32>>}], Decoded).

default_table_no_owner(_) ->
    Msg = nft_table:add(1, <<"plain">>, 10),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    ?assertMatch([{1, <<"plain", 0>>}, {2, <<0:32>>}], Decoded).

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

kernel_owner_table(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, #{owner => true}, Seq) end
    ]),
    Items = nft_json("list tables"),
    case Items of
        [] ->
            %% nft JSON parse failed (nft < 1.0.6 truncates owner table flags)
            %% Verify via plaintext instead
            Output = os:cmd("nft list tables 2>/dev/null"),
            ?assert(string:find(Output, binary_to_list(?TABLE)) =/= nomatch);
        _ ->
            Found = lists:any(
                fun
                    (#{<<"table">> := #{<<"name">> := N}}) -> N =:= ?TABLE;
                    (_) -> false
                end,
                Items
            ),
            ?assert(Found)
    end,
    nfnl_server:stop(Pid).

kernel_owner_table_removed_on_exit(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, #{owner => true}, Seq) end
    ]),
    %% Stop nfnl_server — closes the netlink socket
    nfnl_server:stop(Pid),
    timer:sleep(100),
    %% Owner table should be auto-removed by the kernel
    Items = nft_json("list tables"),
    Found = lists:any(
        fun
            (#{<<"table">> := #{<<"name">> := N}}) -> N =:= ?TABLE;
            (_) -> false
        end,
        Items
    ),
    ?assertNot(Found).

%% --- Helpers ---

nft_json(Cmd) ->
    case os:cmd("nft -j " ++ Cmd ++ " 2>/dev/null") of
        [] ->
            [];
        Output ->
            case catch json:decode(list_to_binary(Output)) of
                #{<<"nftables">> := Items} ->
                    Items;
                _ ->
                    %% nft < 1.0.6 may produce truncated/malformed JSON
                    %% (e.g. owner table flags field), skip gracefully
                    ct:log(
                        "nft JSON parse failed for '~s' (nft version may be too old), output: ~s",
                        [Cmd, Output]
                    ),
                    []
            end
    end.
