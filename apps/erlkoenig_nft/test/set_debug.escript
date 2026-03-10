#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(INET, 1).

main(_) ->
    os:cmd("nft delete table inet banfw 2>/dev/null"),
    {ok, Srv} = nfnl_server:start_link(),
    T = <<"banfw">>,

    %% Step 1: Table
    io:format("Table: ~p~n", [nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_table:add(?INET, T, S) end
    ])]),

    %% Step 2: Chain
    io:format("Chain: ~p~n", [nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => <<"input">>,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, S) end
    ])]),

    %% Step 3: Set
    io:format("Set: ~p~n", [nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_set:add(?INET, #{
            table => T, name => <<"banned">>,
            type => ipv4_addr, id => 1
        }, S) end
    ])]),

    %% Step 4: Rule with lookup
    io:format("Rule: ~p~n", [nfnl_server:apply_msgs(Srv, [
        nft_rules:set_lookup_drop(T, <<"input">>, <<"banned">>, 1)
    ])]),

    nfnl_server:stop(Srv),
    io:format("~s", [os:cmd("nft list ruleset")]),
    os:cmd("nft delete table inet banfw 2>/dev/null").
