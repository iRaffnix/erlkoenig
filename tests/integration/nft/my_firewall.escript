#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig/ebin

-define(INET, 1).

main(["up"]) ->
    firewall_up();
main(["down"]) ->
    firewall_down();
main(_) ->
    io:format("Usage: my_firewall.escript up|down~n").

firewall_up() ->
    os:cmd("nft delete table inet erlwall 2>/dev/null"),

    {ok, Srv} = nfnl_server:start_link(),
    T = <<"erlwall">>,
    I = <<"input">>,

    ok = nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_table:add(?INET, T, S) end,
        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => I,
            hook => input, type => filter,
            priority => 0, policy => drop
        }, S) end,
        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => <<"output">>,
            hook => output, type => filter,
            priority => 0, policy => accept
        }, S) end,

        nft_rules:ct_established_accept(T, I),
        nft_rules:iif_accept(T, I),
        nft_rules:tcp_accept(T, I, 22),
        nft_rules:tcp_accept(T, I, 80),
        nft_rules:tcp_accept(T, I, 443),
        nft_rules:protocol_accept(T, I, icmp),
        nft_rules:protocol_accept(T, I, icmpv6)
    ]),

    nfnl_server:stop(Srv),
    io:format("~n=== Erlkönig Firewall UP ===~n~n"),
    io:format("~s", [os:cmd("nft list ruleset")]).

firewall_down() ->
    os:cmd("nft delete table inet erlwall"),
    io:format("=== Erlkönig Firewall DOWN ===~n").
