#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(INET, 1).

main(_) ->
    os:cmd("nft delete table inet qtest 2>/dev/null"),

    {ok, Srv} = nfnl_server:start_link(),
    T = <<"qtest">>,
    I = <<"input">>,

    %% Setup
    ok = nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_table:add(?INET, T, S) end,
        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => I,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, S) end,
        nft_rules:tcp_accept_count(T, I, 22),
        nft_rules:tcp_accept_count(T, I, 80)
    ]),

    %% Query via Netlink
    {ok, Sock} = nfnl_socket:open(),

    io:format("=== Tables ===~n"),
    {ok, Tables} = nft_query:list_tables(Sock, ?INET),
    io:format("~p~n~n", [Tables]),

    io:format("=== Chains in qtest ===~n"),
    {ok, Chains} = nft_query:list_chains(Sock, ?INET, T),
    io:format("~p~n~n", [Chains]),

    io:format("=== Rules in qtest ===~n"),
    {ok, Rules} = nft_query:list_rules(Sock, ?INET, T),
    io:format("~p~n~n", [Rules]),

    io:format("=== Full Ruleset ===~n"),
    {ok, Ruleset} = nft_query:get_ruleset(Sock, ?INET),
    io:format("~p~n~n", [Ruleset]),

    nfnl_socket:close(Sock),

    %% Delete via Netlink (no os:cmd!)
    io:format("=== Delete table via Netlink ===~n"),
    ok = nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_delete:table(?INET, T, S) end
    ]),

    %% Verify it's gone
    {ok, Sock2} = nfnl_socket:open(),
    {ok, TablesAfter} = nft_query:list_tables(Sock2, ?INET),
    io:format("Tables after delete: ~p~n", [TablesAfter]),
    nfnl_socket:close(Sock2),

    nfnl_server:stop(Srv),
    io:format("=== Done ===~n").
