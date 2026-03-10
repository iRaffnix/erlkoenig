#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 08: File Injection (write files into container before execve)
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 08: File Injection ===~n~n"),
    test_helper:boot(),

    Pid = test_helper:step("Container mit injected files spawnen", fun() ->
        {ok, P} = erlkoenig_core:spawn(test_helper:demo("sleeper"),
            #{ip => {10,0,0,10},
              args => [<<"30">>],
              files => #{
                  <<"/etc/hostname">> => <<"erlkoenig-test-container\n">>,
                  <<"/etc/config.json">> => <<"{\"port\": 8080, \"debug\": true}\n">>

              }}),
        io:format("    Injected: /etc/hostname, /etc/config.json~n"),
        timer:sleep(1000),
        {ok, P}
    end),

    %% Verify files via /proc/<pid>/root (no cat needed)
    test_helper:step("Verify /etc/hostname", fun() ->
        Info = erlkoenig_core:inspect(Pid),
        OsPid = maps:get(os_pid, Info),
        Path = lists:flatten(io_lib:format("/proc/~p/root/etc/hostname", [OsPid])),
        {ok, Content} = file:read_file(Path),
        Result = string:trim(binary_to_list(Content)),
        io:format("    /etc/hostname = ~s~n", [Result]),
        case Result of
            "erlkoenig-test-container" -> ok;
            _ -> {error, {unexpected_content, Result}}
        end
    end),

    test_helper:step("Verify /etc/config.json", fun() ->
        Info = erlkoenig_core:inspect(Pid),
        OsPid = maps:get(os_pid, Info),
        Path = lists:flatten(io_lib:format("/proc/~p/root/etc/config.json", [OsPid])),
        {ok, Content} = file:read_file(Path),
        Result = string:trim(binary_to_list(Content)),
        io:format("    /etc/config.json = ~s~n", [Result]),
        case string:find(Result, "8080") of
            nomatch -> {error, {unexpected_content, Result}};
            _ -> ok
        end
    end),

    test_helper:cleanup([Pid]),
    io:format("~n=== Test 08 bestanden ===~n~n"),
    halt(0).
