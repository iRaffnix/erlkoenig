-module(nft_flowtable_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").
-define(TABLE, <<"erltest_ft">>).
-define(FT_NAME, <<"ft0">>).
-define(CHAIN, <<"forward">>).

all() ->
    [
        {group, unit},
        {group, kernel}
    ].

groups() ->
    [
        {unit, [parallel], [
            flowtable_msg_type,
            flowtable_has_hook_nested,
            flowtable_has_devices,
            flowtable_has_flags,
            flowtable_no_devices,
            offload_ir_structure,
            offload_ir_encode,
            flow_offload_rule_structure
        ]},
        {kernel, [], [
            kernel_create_flowtable,
            kernel_flowtable_with_rule
        ]}
    ].

init_per_group(kernel, Config) ->
    case os:cmd("id -u") of
        "0\n" ->
            os:cmd("modprobe nf_flow_table 2>/dev/null"),
            Config;
        _ ->
            {skip, "kernel tests require root"}
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

flowtable_msg_type(_) ->
    Msg = nft_flowtable:add(
        ?NFPROTO_INET,
        #{
            table => <<"fw">>,
            name => <<"ft0">>,
            hook => ingress,
            priority => 0,
            devices => [<<"lo">>]
        },
        100
    ),
    %% NFT_MSG_NEWFLOWTABLE = 0x16 = 22
    %% Type = (NFNL_SUBSYS_NFTABLES(10) bsl 8) bor 22 = 2582
    <<_Len:32/little, 2582:16/little, _/binary>> = Msg.

flowtable_has_hook_nested(_) ->
    Msg = nft_flowtable:add(
        ?NFPROTO_INET,
        #{
            table => <<"fw">>,
            name => <<"ft0">>,
            hook => ingress,
            priority => 10,
            devices => [<<"lo">>]
        },
        1
    ),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    %% NFTA_FLOWTABLE_HOOK(3) should be nested
    Hook = lists:keyfind(3, 1, Decoded),
    ?assertMatch({3, nested, _}, Hook),
    {3, nested, HookAttrs} = Hook,
    %% NFTA_FLOWTABLE_HOOK_NUM(1) = NF_NETDEV_INGRESS(0)
    ?assertMatch({1, <<0:32/big>>}, lists:keyfind(1, 1, HookAttrs)),
    %% NFTA_FLOWTABLE_HOOK_PRIORITY(2) = 10
    ?assertMatch({2, <<10:32/big>>}, lists:keyfind(2, 1, HookAttrs)).

flowtable_has_devices(_) ->
    Msg = nft_flowtable:add(
        ?NFPROTO_INET,
        #{
            table => <<"fw">>,
            name => <<"ft0">>,
            hook => ingress,
            devices => [<<"lo">>, <<"eth0">>]
        },
        1
    ),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    %% NFTA_FLOWTABLE_DEVS(4) should be nested
    Devs = lists:keyfind(4, 1, Decoded),
    ?assertMatch({4, nested, _}, Devs),
    {4, nested, DevAttrs} = Devs,
    %% Should contain two NFTA_DEVICE_NAME(1) entries
    DevNames = [V || {1, V} <- DevAttrs],
    ?assertEqual(2, length(DevNames)),
    ?assertMatch(<<"lo", 0>>, lists:nth(1, DevNames)),
    ?assertMatch(<<"eth0", 0>>, lists:nth(2, DevNames)).

flowtable_has_flags(_) ->
    Msg = nft_flowtable:add(
        ?NFPROTO_INET,
        #{
            table => <<"fw">>,
            name => <<"ft0">>,
            hook => ingress,
            devices => [<<"lo">>],
            %% hardware offload
            flags => 1
        },
        1
    ),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    %% NFTA_FLOWTABLE_FLAGS(6) = 1
    ?assertMatch({6, <<1:32/big>>}, lists:keyfind(6, 1, Decoded)).

flowtable_no_devices(_) ->
    %% Flowtable with no devices should still encode successfully
    Msg = nft_flowtable:add(
        ?NFPROTO_INET,
        #{
            table => <<"fw">>,
            name => <<"ft0">>,
            hook => ingress
        },
        1
    ),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    %% NFTA_FLOWTABLE_DEVS(4) should not be present
    ?assertEqual(false, lists:keyfind(4, 1, Decoded)).

offload_ir_structure(_) ->
    Term = nft_expr_ir:offload(<<"ft0">>),
    ?assertMatch({offload, #{table_name := <<"ft0">>}}, Term).

offload_ir_encode(_) ->
    Term = nft_expr_ir:offload(<<"ft0">>),
    Bin = nft_encode:expr(Term),
    Decoded = nfnl_attr:decode(Bin),
    {1, <<"flow_offload", 0>>} = lists:keyfind(1, 1, Decoded),
    {2, nested, ExprAttrs} = lists:keyfind(2, 1, Decoded),
    %% NFTA_FLOW_TABLE_NAME(1) = "ft0"
    ?assertMatch({1, <<"ft0", 0>>}, lists:keyfind(1, 1, ExprAttrs)).

flow_offload_rule_structure(_) ->
    Rule = nft_rules:flow_offload(<<"ft0">>),
    ?assertEqual(4, length(Rule)),
    %% ct state, bitwise, cmp neq, offload
    ?assertMatch({ct, #{key := state}}, lists:nth(1, Rule)),
    ?assertMatch({bitwise, _}, lists:nth(2, Rule)),
    ?assertMatch({cmp, #{op := neq}}, lists:nth(3, Rule)),
    ?assertMatch({offload, #{table_name := <<"ft0">>}}, lists:nth(4, Rule)).

%% ===================================================================
%% Kernel tests
%% ===================================================================

kernel_create_flowtable(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_flowtable:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?FT_NAME,
                    hook => ingress,
                    priority => 0,
                    devices => [<<"lo">>]
                },
                Seq
            )
        end
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Find the flowtable in the JSON output
    Flowtables = [F || #{<<"flowtable">> := F} <- Items],
    ?assertMatch([#{<<"name">> := ?FT_NAME}], Flowtables),
    [Ft] = Flowtables,
    ?assertEqual(?FT_NAME, maps:get(<<"name">>, Ft)),
    ?assertEqual(<<"ingress">>, maps:get(<<"hook">>, Ft)),
    ?assertEqual(0, maps:get(<<"prio">>, Ft)),
    nfnl_server:stop(Pid).

kernel_flowtable_with_rule(_Config) ->
    {ok, Pid} = nfnl_server:start_link(),
    OffloadRule = nft_rules:flow_offload(?FT_NAME),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, ?TABLE, Seq) end,
        fun(Seq) ->
            nft_flowtable:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?FT_NAME,
                    hook => ingress,
                    priority => 0,
                    devices => [<<"lo">>]
                },
                Seq
            )
        end,
        fun(Seq) ->
            nft_chain:add(
                ?NFPROTO_INET,
                #{
                    table => ?TABLE,
                    name => ?CHAIN,
                    hook => forward,
                    type => filter,
                    priority => 0,
                    policy => accept
                },
                Seq
            )
        end,
        nft_encode:rule_fun(inet, ?TABLE, ?CHAIN, OffloadRule)
    ]),
    Items = nft_json("list table inet " ++ binary_to_list(?TABLE)),
    %% Verify flowtable exists
    Flowtables = [F || #{<<"flowtable">> := F} <- Items],
    ?assertMatch([#{<<"name">> := ?FT_NAME}], Flowtables),
    %% Verify chain exists
    Chains = [C || #{<<"chain">> := C = #{<<"name">> := ?CHAIN}} <- Items],
    ?assertEqual(1, length(Chains)),
    %% Verify rule has flow/offload expression
    Rules = [R || #{<<"rule">> := R} <- Items],
    ?assert(length(Rules) >= 1),
    %% Check that the rule contains a flow expression referencing our flowtable
    [Rule | _] = Rules,
    Exprs = maps:get(<<"expr">>, Rule, []),
    HasFlow = lists:any(
        fun
            (#{<<"flow">> := _}) -> true;
            (_) -> false
        end,
        Exprs
    ),
    ?assert(HasFlow),
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
