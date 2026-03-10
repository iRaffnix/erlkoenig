-module(nfnl_server_SUITE).
-moduledoc false.
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-define(NFPROTO_INET, 1).

all() ->
    [{group, unit},
     {group, kernel}].

groups() ->
    [{unit, [parallel], [
        start_stop
     ]},
     {kernel, [], [
        create_table,
        create_table_and_chain,
        create_table_idempotent,
        full_rule
     ]}].

init_per_group(kernel, Config) ->
    case os:cmd("id -u") of
        "0\n" -> Config;
        _ -> {skip, "kernel tests require root"}
    end;
init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

init_per_testcase(TC, Config) when
      TC =:= create_table;
      TC =:= create_table_and_chain;
      TC =:= create_table_idempotent;
      TC =:= full_rule ->
    os:cmd("nft delete table inet erltest 2>/dev/null"),
    Config;
init_per_testcase(_TC, Config) ->
    Config.

end_per_testcase(TC, _Config) when
      TC =:= create_table;
      TC =:= create_table_and_chain;
      TC =:= create_table_idempotent;
      TC =:= full_rule ->
    os:cmd("nft delete table inet erltest 2>/dev/null"),
    ok;
end_per_testcase(_TC, _Config) ->
    ok.

start_stop(_) ->
    {ok, Pid} = nfnl_server:start_link(),
    ?assert(is_process_alive(Pid)),
    ok = nfnl_server:stop(Pid).

create_table(_) ->
    {ok, Pid} = nfnl_server:start_link(),
    Result = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, <<"erltest">>, Seq) end
    ]),
    ?assertEqual(ok, Result),
    Output = os:cmd("nft list table inet erltest"),
    ?assertNotEqual([], Output),
    nfnl_server:stop(Pid).

create_table_and_chain(_) ->
    {ok, Pid} = nfnl_server:start_link(),
    Result = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, <<"erltest">>, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => <<"erltest">>,
            name  => <<"input">>,
            hook  => input,
            type  => filter,
            priority => 0,
            policy   => accept
        }, Seq) end
    ]),
    ?assertEqual(ok, Result),
    Output = os:cmd("nft list chain inet erltest input"),
    ?assertNotEqual([], Output),
    nfnl_server:stop(Pid).

create_table_idempotent(_) ->
    {ok, Pid} = nfnl_server:start_link(),
    ok = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, <<"erltest">>, Seq) end
    ]),
    Result = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, <<"erltest">>, Seq) end
    ]),
    ?assertEqual(ok, Result),
    nfnl_server:stop(Pid).

full_rule(_) ->
    {ok, Pid} = nfnl_server:start_link(),
    Result = nfnl_server:apply_msgs(Pid, [
        fun(Seq) -> nft_table:add(?NFPROTO_INET, <<"erltest">>, Seq) end,
        fun(Seq) -> nft_chain:add(?NFPROTO_INET, #{
            table => <<"erltest">>,
            name  => <<"input">>,
            hook  => input,
            type  => filter,
            priority => 0,
            policy   => accept
        }, Seq) end,
        fun(Seq) -> nft_rule:add(?NFPROTO_INET, <<"erltest">>, <<"input">>, [
            nft_expr_meta:load(l4proto, 1),
            nft_expr_cmp:eq(1, <<6>>),
            nft_expr_payload:tcp_dport(1),
            nft_expr_cmp:eq(1, <<0, 80>>),
            nft_expr_immediate:accept()
        ], Seq) end
    ]),
    ?assertEqual(ok, Result),
    Output = os:cmd("nft list ruleset"),
    ?assertNotEqual(nomatch, string:find(Output, "tcp dport 80 accept")),
    nfnl_server:stop(Pid).
