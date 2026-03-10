#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

main(_) ->
    Config = #{
        table => <<"erlkfw">>,
        sets => [
            {<<"blocklist">>, ipv4_addr}
        ],
        counters => [ssh, http, banned, dropped],
        chains => [
            #{name => <<"input">>, hook => input, type => filter,
              priority => 0, policy => accept,
              rules => [
                  ct_established_accept,
                  iif_accept,
                  {set_lookup_drop, <<"blocklist">>, banned},
                  {tcp_accept, 22, ssh},
                  {tcp_accept, 80, http},
                  {tcp_accept, 443, http},
                  {protocol_accept, icmp},
                  {protocol_accept, icmpv6},
                  {log_drop, <<"ERLKOENIG: ">>, dropped}
              ]}
        ],
        watch => #{
            interval => 2000,
            thresholds => [
                {ssh_flood,    ssh,     pps, '>', 50.0},
                {ddos_alert,   dropped, pps, '>', 1000.0},
                {ban_activity, banned,  pps, '>', 0.0}
            ]
        }
    },

    io:format("=== Applying Config ===~n"),
    {ok, Watcher} = erlk_firewall:apply(Config),
    io:format("Watcher: ~p~n~n", [Watcher]),

    io:format("~s~n", [os:cmd("nft list ruleset")]),

    %% Let it watch for a moment
    timer:sleep(3000),

    io:format("=== Rates ===~n"),
    Rates = erlk_watch:get_rates(Watcher),
    io:format("~p~n~n", [Rates]),

    io:format("=== Teardown ===~n"),
    ok = erlk_firewall:teardown(Config, Watcher),

    io:format("~s", [os:cmd("nft list ruleset")]),
    io:format("=== Done ===~n").
