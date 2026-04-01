#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 09: DNS Service Discovery
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 09: DNS Service Discovery ===~n~n"),
    test_helper:boot(),

    {P1, P2} = test_helper:step("2 benannte Container spawnen", fun() ->
        {ok, A} = erlkoenig:spawn(test_helper:demo("echo_server"),
            #{ip => {10,0,0,10}, args => [<<"7001">>],
              name => <<"webserver">>}),
        {ok, B} = erlkoenig:spawn(test_helper:demo("echo_server"),
            #{ip => {10,0,0,20}, args => [<<"7002">>],
              name => <<"database">>}),
        io:format("    webserver=10.0.0.10  database=10.0.0.20~n"),
        timer:sleep(1000),
        {ok, {A, B}}
    end),

    %% DNS lookup via zone API
    DnsPid = erlkoenig_zone:dns(default),

    test_helper:step("DNS: webserver.erlkoenig -> 10.0.0.10", fun() ->
        case gen_server:call(DnsPid, {lookup, <<"webserver">>}) of
            {ok, {10,0,0,10}} ->
                io:format("    webserver.erlkoenig -> 10.0.0.10~n"),
                ok;
            {ok, Other} ->
                {error, {wrong_ip, Other}};
            not_found ->
                {error, not_found}
        end
    end),

    test_helper:step("DNS: database.erlkoenig -> 10.0.0.20", fun() ->
        case gen_server:call(DnsPid, {lookup, <<"database">>}) of
            {ok, {10,0,0,20}} ->
                io:format("    database.erlkoenig -> 10.0.0.20~n"),
                ok;
            {ok, Other} ->
                {error, {wrong_ip, Other}};
            not_found ->
                {error, not_found}
        end
    end),

    %% Reach by resolved IP
    test_helper:step("Echo via DNS-aufgeloeste IP", fun() ->
        {ok, Ip} = gen_server:call(DnsPid, {lookup, <<"webserver">>}),
        test_helper:echo_test(Ip, 7001, <<"Hello via DNS!">>)
    end),

    test_helper:cleanup([P1, P2]),
    io:format("~n=== Test 09 bestanden ===~n~n"),
    halt(0).
