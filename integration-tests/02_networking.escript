#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 02: Container-to-Container Networking via Bridge
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 02: Container Networking ===~n~n"),
    test_helper:boot(),

    %% Spawn two echo servers
    {P1, P2} = test_helper:step("2 Echo-Server spawnen", fun() ->
        {ok, A} = erlkoenig:spawn(test_helper:demo("echo_server"),
            #{ip => {10,0,0,10}, args => [<<"7001">>]}),
        {ok, B} = erlkoenig:spawn(test_helper:demo("echo_server"),
            #{ip => {10,0,0,20}, args => [<<"7002">>]}),
        io:format("    A=10.0.0.10:7001  B=10.0.0.20:7002~n"),
        timer:sleep(1000),
        {ok, {A, B}}
    end),

    %% Host -> Container A
    test_helper:step("Host -> Container A (10.0.0.10:7001)", fun() ->
        test_helper:echo_test({10,0,0,10}, 7001, <<"Host says hi to A!">>)
    end),

    %% Host -> Container B
    test_helper:step("Host -> Container B (10.0.0.20:7002)", fun() ->
        test_helper:echo_test({10,0,0,20}, 7002, <<"Host says hi to B!">>)
    end),

    %% Cleanup
    test_helper:cleanup([P1, P2]),
    io:format("~n=== Test 02 bestanden ===~n~n"),
    halt(0).
