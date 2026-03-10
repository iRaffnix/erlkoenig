#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(INET, 1).

main(_) ->
    os:cmd("nft delete table inet logfw 2>/dev/null"),

    {ok, Srv} = nfnl_server:start_link(),
    T = <<"logfw">>,
    I = <<"input">>,

    ok = nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_table:add(?INET, T, S) end,
        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => I,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, S) end,
        nft_rules:ct_established_accept(T, I),
        nft_rules:iif_accept(T, I),
        nft_rules:tcp_accept_count(T, I, 22),
        nft_rules:tcp_accept_count(T, I, 80),
        nft_rules:log_drop_count(T, I, <<"ERLKOENIG_DROP: ">>)
    ]),

    nfnl_server:stop(Srv),
    io:format("~s", [os:cmd("nft list ruleset")]),
    os:cmd("nft delete table inet logfw").
