#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(INET, 1).

main(_) ->
    %% Clean up ALL tables to avoid priority conflicts
    os:cmd("nft delete table inet demo 2>/dev/null"),
    os:cmd("nft delete table inet wtest 2>/dev/null"),

    {ok, Srv} = nfnl_server:start_link(),
    T = <<"wtest">>,
    I = <<"input">>,

    ok = nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_table:add(?INET, T, S) end,
        fun(S) -> nft_object:add_counter(?INET, T, <<"ssh_pkts">>, S) end,
        fun(S) -> nft_object:add_counter(?INET, T, <<"dropped">>, S) end,
        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => I,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, S) end,
        nft_rules:ct_established_accept(T, I),
        nft_rules:tcp_accept_named(T, I, 22, <<"ssh_pkts">>),
        nft_rules:log_drop_named(T, I, <<"DROP: ">>, <<"dropped">>)
    ]),
    nfnl_server:stop(Srv),

    io:format("~s~n", [os:cmd("nft list ruleset")]),

    %% Subscribe to events
    pg:start(erlkoenig_nft),
    pg:join(erlkoenig_nft, counter_events, self()),

    %% Start watcher with 2s interval
    {ok, Watcher} = erlkoenig_nft_watch:start_link(#{
        family => ?INET,
        table => T,
        counters => [<<"ssh_pkts">>, <<"dropped">>],
        interval => 2000
    }),

    %% Add threshold: alert if SSH > 0 pps
    erlkoenig_nft_watch:add_threshold(Watcher, ssh_alert,
        <<"ssh_pkts">>, pps,
        {fun(Name, _Metric, Val, _Thresh) ->
            io:format("  ALERT: ~s at ~.1f pps~n", [Name, Val])
        end, '>', 0.0}),

    %% Wait for exactly 3 poll cycles
    io:format("=== Watching for 3 cycles ===~n"),
    wait_cycles(3),

    %% Show final rates
    io:format("~n=== Final Rates ===~n"),
    Rates = erlkoenig_nft_watch:get_rates(Watcher),
    io:format("~p~n", [Rates]),

    erlkoenig_nft_watch:stop(Watcher),
    os:cmd("nft delete table inet wtest"),
    io:format("~n=== Done ===~n").

wait_cycles(0) -> ok;
wait_cycles(N) ->
    receive
        {counter_event, Name, Rate} ->
            io:format("[cycle ~B] ~s: ~.1f pps, ~.1f bps (~B pkts, ~B bytes)~n",
                      [N, Name, maps:get(pps, Rate), maps:get(bps, Rate),
                       maps:get(packets, Rate), maps:get(bytes, Rate)]);
        {threshold_event, Name, Metric, Val, Thresh} ->
            io:format("[cycle ~B] THRESHOLD ~s ~p: ~.1f > ~.1f~n",
                      [N, Name, Metric, Val, Thresh])
    after 3000 ->
        io:format("[cycle ~B] timeout~n", [N]),
        wait_cycles(N - 1)
    end,
    %% Drain remaining events for this cycle
    drain(),
    wait_cycles(N - 1).

drain() ->
    receive
        {counter_event, _, _} -> drain();
        {threshold_event, _, _, _, _} -> drain()
    after 100 ->
        ok
    end.
