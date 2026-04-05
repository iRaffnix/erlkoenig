#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 10: Firewall Isolation (per-container rules)
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 10: Firewall Isolation ===~n~n"),
    test_helper:boot(),

    {P1, P2} = test_helper:step("2 Container mit unterschiedlichen Firewall-Regeln", fun() ->
        %% Container A: strict firewall, only port 7001 allowed
        {ok, A} = erlkoenig:spawn(test_helper:demo("echo_server"),
            #{ip => {10,0,0,10}, args => [<<"7001">>],
              firewall => #{chains => [#{
                  name => <<"inbound">>, priority => 0,
                  type => filter, hook => input, policy => drop,
                  rules => [ct_established_accept, icmp_accept,
                            {tcp_accept, 7001}]
              }]}}),
        %% Container B: open firewall (default rules allow everything)
        {ok, B} = erlkoenig:spawn(test_helper:demo("echo_server"),
            #{ip => {10,0,0,20}, args => [<<"7002">>]}),
        io:format("    A: strict (nur Port 7001)  B: open~n"),
        timer:sleep(1000),
        {ok, {A, B}}
    end),

    %% Allowed port works
    test_helper:step("Container A: Port 7001 erlaubt", fun() ->
        test_helper:echo_test({10,0,0,10}, 7001, <<"Firewall allows this!">>)
    end),

    %% Container B works (open)
    test_helper:step("Container B: Port 7002 erlaubt (open)", fun() ->
        test_helper:echo_test({10,0,0,20}, 7002, <<"Open firewall!">>)
    end),

    %% Verify per-container chains exist
    test_helper:step("Per-Container nft-Chains vorhanden", fun() ->
        Output = os:cmd("nft list table inet erlkoenig 2>&1"),
        case string:find(Output, "tcp dport 7001 accept") of
            nomatch -> {error, "Port 7001 accept rule missing"};
            _ ->
                io:format("    tcp dport 7001 accept - vorhanden~n"),
                ok
        end
    end),

    test_helper:cleanup([P1, P2]),
    io:format("~n=== Test 10 bestanden ===~n~n"),
    halt(0).
