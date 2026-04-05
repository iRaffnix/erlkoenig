-module(nft_chain_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_chn">>).
-define(CHAIN, <<"input">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            add_input_chain,
            chain_has_hook_nested,
            chain_policy_accept,
            chain_policy_drop
        ]},
        {kernel, [], [
            kernel_create_input_chain,
            kernel_chain_hook,
            kernel_chain_policy_accept,
            kernel_chain_policy_drop
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

add_input_chain(_) ->
    Msg = nft_chain:add(
        1,
        #{
            table => <<"fw">>,
            name => <<"input">>,
            hook => input,
            type => filter,
            priority => 0,
            policy => accept
        },
        100
    ),
    <<_Len:32/little, 2563:16/little, _/binary>> = Msg.

chain_has_hook_nested(_) ->
    Msg = nft_chain:add(
        1,
        #{
            table => <<"fw">>,
            name => <<"input">>,
            hook => input,
            priority => 100
        },
        1
    ),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    %% NFTA_CHAIN_HOOK(4) should be nested
    Hook = lists:keyfind(4, 1, Decoded),
    ?assertMatch({4, nested, _}, Hook),
    {4, nested, HookAttrs} = Hook,
    %% NFTA_HOOK_HOOKNUM(1) = NF_INET_LOCAL_IN(1)
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, HookAttrs)),
    %% NFTA_HOOK_PRIORITY(2) = 100
    ?assertMatch({2, <<100:32/big>>}, lists:keyfind(2, 1, HookAttrs)).

chain_policy_accept(_) ->
    Msg = nft_chain:add(
        1,
        #{
            table => <<"fw">>,
            name => <<"in">>,
            hook => input,
            policy => accept
        },
        1
    ),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    %% NFTA_CHAIN_POLICY(5) = NF_ACCEPT(1)
    ?assertMatch({5, <<1:32/big>>}, lists:keyfind(5, 1, Decoded)).

chain_policy_drop(_) ->
    Msg = nft_chain:add(
        1,
        #{
            table => <<"fw">>,
            name => <<"fwd">>,
            hook => forward,
            policy => drop
        },
        1
    ),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    ?assertMatch({5, <<0:32/big>>}, lists:keyfind(5, 1, Decoded)).

%% --- Kernel tests ---

kernel_create_input_chain(_Config) ->
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
        end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    [Chain] = [C || #{<<"chain">> := C = #{<<"name">> := ?CHAIN}} <- Items],
    ?assertEqual(?CHAIN, maps:get(<<"name">>, Chain)),
    nfnl_server:stop(Pid).

kernel_chain_hook(_Config) ->
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
                    priority => 100,
                    policy => accept
                },
                Seq
            )
        end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    [Chain] = [C || #{<<"chain">> := C = #{<<"name">> := ?CHAIN}} <- Items],
    ?assertEqual(<<"filter">>, maps:get(<<"type">>, Chain)),
    ?assertEqual(<<"input">>, maps:get(<<"hook">>, Chain)),
    ?assertEqual(100, maps:get(<<"prio">>, Chain)),
    nfnl_server:stop(Pid).

kernel_chain_policy_accept(_Config) ->
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
        end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    [Chain] = [C || #{<<"chain">> := C = #{<<"name">> := ?CHAIN}} <- Items],
    ?assertEqual(<<"accept">>, maps:get(<<"policy">>, Chain)),
    nfnl_server:stop(Pid).

kernel_chain_policy_drop(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => <<"fwd">>,
                    hook => forward,
                    type => filter,
                    priority => 0,
                    policy => drop
                },
                Seq
            )
        end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    [Chain] = [C || #{<<"chain">> := C = #{<<"name">> := <<"fwd">>}} <- Items],
    ?assertEqual(<<"drop">>, maps:get(<<"policy">>, Chain)),
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
