#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(INET, 1).

main(_) ->
    os:cmd("nft delete table inet nctest 2>/dev/null"),

    {ok, Srv} = nfnl_server:start_link(),
    T = <<"nctest">>,
    I = <<"input">>,

    %% Setup: table + named counters + chain + rules
    io:format("=== Setup ===~n"),
    ok = nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_table:add(?INET, T, S) end,

        %% Named counters
        fun(S) -> nft_object:add_counter(?INET, T, <<"ssh_pkts">>, S) end,
        fun(S) -> nft_object:add_counter(?INET, T, <<"http_pkts">>, S) end,
        fun(S) -> nft_object:add_counter(?INET, T, <<"dropped">>, S) end,

        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => I,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, S) end,

        nft_rules:ct_established_accept(T, I),
        nft_rules:iif_accept(T, I),
        nft_rules:tcp_accept_named(T, I, 22, <<"ssh_pkts">>),
        nft_rules:tcp_accept_named(T, I, 80, <<"http_pkts">>),
        nft_rules:log_drop_named(T, I, <<"DROPPED: ">>, <<"dropped">>)
    ]),

    io:format("~s~n", [os:cmd("nft list ruleset")]),

    %% Query named counters
    {ok, Sock} = nfnl_socket:open(),

    io:format("=== All Counters ===~n"),
    {ok, All} = nft_object:get_all_counters(Sock, ?INET, T),
    io:format("~p~n~n", [All]),

    io:format("=== SSH Counter ===~n"),
    {ok, Ssh} = nft_object:get_counter(Sock, ?INET, T, <<"ssh_pkts">>),
    io:format("~p~n~n", [Ssh]),

    io:format("=== SSH Counter Reset ===~n"),
    {ok, SshReset} = nft_object:get_counter_reset(Sock, ?INET, T, <<"ssh_pkts">>),
    io:format("Before reset: ~p~n", [SshReset]),

    {ok, SshAfter} = nft_object:get_counter(Sock, ?INET, T, <<"ssh_pkts">>),
    io:format("After reset:  ~p~n~n", [SshAfter]),

    nfnl_socket:close(Sock),
    nfnl_server:stop(Srv),
    os:cmd("nft delete table inet nctest"),
    io:format("=== Done ===~n").
