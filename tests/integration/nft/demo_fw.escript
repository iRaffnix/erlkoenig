#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig/ebin

-define(INET, 1).

main(_) ->
    os:cmd("nft delete table inet demo 2>/dev/null"),

    {ok, Srv} = nfnl_server:start_link(),
    T = <<"demo">>,
    I = <<"input">>,

    ok = nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_table:add(?INET, T, S) end,
        fun(S) -> nft_set:add(?INET, #{
            table => T, name => <<"banned">>,
            type => ipv4_addr, id => 1
        }, S) end,
        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => I,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, S) end,
        nft_rules:ct_established_accept(T, I),
        nft_rules:iif_accept(T, I),
        nft_rules:set_lookup_drop_count(T, I, <<"banned">>, 1),
        nft_rules:tcp_accept_count(T, I, 22),
        nft_rules:tcp_accept_count(T, I, 80),
        nft_rules:tcp_accept_count(T, I, 443),
        nft_rules:protocol_accept(T, I, icmp),
        nft_rules:protocol_accept(T, I, icmpv6),
        nft_rules:log_drop_count(T, I, <<"ERLKOENIG: ">>)
    ]),

    nfnl_server:stop(Srv),
    io:format("~s", [os:cmd("nft list ruleset")]),
    io:format("~nFirewall active. Dashboard should show live data.~n").
