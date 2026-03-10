#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 03: DNAT Port-Forwarding (Host:Port -> Container:Port)
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 03: Port-Forwarding (DNAT) ===~n~n"),
    test_helper:boot(),

    Pid = test_helper:step("Echo-Server mit Port-Forwarding spawnen", fun() ->
        {ok, P} = erlkoenig_core:spawn(test_helper:demo("echo_server"),
            #{ip => {10,0,0,10}, args => [<<"7777">>],
              ports => [{9080, 7777}, {9081, 7777}]}),
        io:format("    Host:9080 -> 10.0.0.10:7777~n"),
        io:format("    Host:9081 -> 10.0.0.10:7777~n"),
        timer:sleep(1000),
        {ok, P}
    end),

    %% Direct via bridge
    test_helper:step("Direct via Bridge (10.0.0.10:7777)", fun() ->
        test_helper:echo_test({10,0,0,10}, 7777, <<"Direct!">>)
    end),

    %% DNAT via gateway (port 9080)
    test_helper:step("DNAT via Gateway (10.0.0.1:9080)", fun() ->
        test_helper:echo_test({10,0,0,1}, 9080, <<"DNAT port 9080!">>)
    end),

    %% DNAT via gateway (port 9081)
    test_helper:step("DNAT via Gateway (10.0.0.1:9081)", fun() ->
        test_helper:echo_test({10,0,0,1}, 9081, <<"DNAT port 9081!">>)
    end),

    %% Verify nft rules
    test_helper:step("nft-Regeln enthalten DNAT", fun() ->
        Output = os:cmd("nft list table inet erlkoenig_ct 2>&1"),
        case {string:find(Output, "9080"), string:find(Output, "9081")} of
            {nomatch, _} -> {error, "Port 9080 nicht in nft-Regeln"};
            {_, nomatch} -> {error, "Port 9081 nicht in nft-Regeln"};
            _ ->
                io:format("    DNAT-Regeln fuer 9080 und 9081 vorhanden~n"),
                ok
        end
    end),

    test_helper:cleanup([Pid]),
    io:format("~n=== Test 03 bestanden ===~n~n"),
    halt(0).
