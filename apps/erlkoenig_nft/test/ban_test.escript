#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(INET, 1).

main(_) ->
    os:cmd("nft delete table inet banfw 2>/dev/null"),

    {ok, Srv} = nfnl_server:start_link(),
    T = <<"banfw">>,
    I = <<"input">>,

    %% Setup: table + chain + set + lookup rule
    io:format("=== Setup ===~n"),
    ok = nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_table:add(?INET, T, S) end,
        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => I,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, S) end,
        fun(S) -> nft_set:add(?INET, #{
            table => T, name => <<"banned">>,
            type => ipv4_addr, id => 1
        }, S) end,
        nft_rules:set_lookup_drop(T, I, <<"banned">>, 1)
    ]),

    io:format("~s~n", [os:cmd("nft list ruleset")]),

    %% Ban 10.0.0.5
    io:format("=== Ban 10.0.0.5 ===~n"),
    ok = nfnl_server:apply_msgs(Srv, [
        nft_rules:ban_ip(T, <<"banned">>, <<10, 0, 0, 5>>)
    ]),
    io:format("~s~n", [os:cmd("nft list set inet banfw banned")]),

    %% Ban 192.168.1.100
    io:format("=== Ban 192.168.1.100 ===~n"),
    ok = nfnl_server:apply_msgs(Srv, [
        nft_rules:ban_ip(T, <<"banned">>, <<192, 168, 1, 100>>)
    ]),
    io:format("~s~n", [os:cmd("nft list set inet banfw banned")]),

    %% Unban 10.0.0.5
    io:format("=== Unban 10.0.0.5 ===~n"),
    ok = nfnl_server:apply_msgs(Srv, [
        nft_rules:unban_ip(T, <<"banned">>, <<10, 0, 0, 5>>)
    ]),
    io:format("~s~n", [os:cmd("nft list set inet banfw banned")]),

    %% Cleanup
    nfnl_server:stop(Srv),
    os:cmd("nft delete table inet banfw"),
    io:format("=== Done ===~n").
