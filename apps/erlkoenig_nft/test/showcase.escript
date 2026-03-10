#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

main(_) ->
    Config = #{
        table => <<"erlkoenig">>,
        sets => [
            {<<"blocklist">>, ipv4_addr}
        ],
        counters => [ssh, http, https, banned, dropped],
        chains => [
            #{name => <<"input">>, hook => input, type => filter,
              priority => 0, policy => drop,
              rules => [
                  ct_established_accept,
                  iif_accept,
                  {set_lookup_drop, <<"blocklist">>, banned},
                  {tcp_accept, 22, ssh},
                  {tcp_accept, 80, http},
                  {tcp_accept, 443, https},
                  {tcp_accept, 4000},
                  {protocol_accept, icmp},
                  {protocol_accept, icmpv6},
                  {log_drop, <<"ERLKOENIG: ">>, dropped}
              ]}
        ],
        watch => #{
            interval => 2000,
            thresholds => [
                {ssh_flood,    ssh,     pps, '>', 50.0},
                {http_flood,   http,    pps, '>', 500.0},
                {ddos_alert,   dropped, pps, '>', 100.0},
                {ban_activity, banned,  pps, '>', 0.0}
            ]
        }
    },

    io:format("~n"),
    io:format("  ╔══════════════════════════════════════╗~n"),
    io:format("  ║          E R L K Ö N I G             ║~n"),
    io:format("  ║    nf_tables firewall platform       ║~n"),
    io:format("  ╚══════════════════════════════════════╝~n~n"),

    io:format("Applying configuration...~n"),
    {ok, Watcher} = erlk_firewall:apply(Config),
    io:format("Watcher started: ~p~n~n", [Watcher]),

    io:format("~s~n", [os:cmd("nft list ruleset")]),

    io:format("Subscribing to events...~n"),
    pg:start(erlkoenig_nft),
    pg:join(erlkoenig_nft, counter_events, self()),

    io:format("~n  Firewall active. Monitoring live.~n"),
    io:format("  Dashboard: http://10.99.182.180:4000~n"),
    io:format("  Press Ctrl+C to stop.~n~n"),

    monitor_loop(Watcher).

monitor_loop(Watcher) ->
    receive
        {counter_event, Name, #{pps := Pps, bps := Bps,
                                 packets := Pkts, bytes := Bytes}} ->
            case Pkts > 0 of
                true ->
                    io:format("  ▸ ~-12s ~6.1f pps  ~8s  (~B pkts)~n",
                              [Name, Pps, format_bytes(Bps), Pkts]);
                false ->
                    ok
            end,
            monitor_loop(Watcher);
        {threshold_event, Name, Metric, Val, Thresh} ->
            io:format("  ⚠ ALERT ~s ~p=~.1f > ~.1f~n",
                      [Name, Metric, Val, Thresh]),
            monitor_loop(Watcher)
    after 10000 ->
        monitor_loop(Watcher)
    end.

format_bytes(Bps) when Bps >= 1048576 ->
    io_lib:format("~.1f MB/s", [Bps / 1048576]);
format_bytes(Bps) when Bps >= 1024 ->
    io_lib:format("~.1f KB/s", [Bps / 1024]);
format_bytes(Bps) ->
    io_lib:format("~.1f B/s", [Bps]).
