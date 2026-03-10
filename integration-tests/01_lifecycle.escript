#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 01: Container Lifecycle (spawn, inspect, stop, exit code)
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 01: Container Lifecycle ===~n~n"),
    test_helper:boot(),

    %% Spawn a sleeper container
    Pid = test_helper:step("Container spawnen", fun() ->
        {ok, P} = erlkoenig_core:spawn(test_helper:demo("sleeper"),
            #{ip => {10,0,0,10}, args => [<<"5">>]}),
        io:format("    pid=~p~n", [P]),
        {ok, P}
    end),

    timer:sleep(500),

    %% Inspect
    test_helper:step("Inspect (state=running)", fun() ->
        Info = erlkoenig_core:inspect(Pid),
        State = maps:get(state, Info),
        Id = maps:get(id, Info),
        OsPid = maps:get(os_pid, Info),
        io:format("    id=~s state=~p os_pid=~p~n", [Id, State, OsPid]),
        case State of
            running -> ok;
            Other -> {error, {expected_running, Other}}
        end
    end),

    %% Stop and verify state
    test_helper:step("Stop (graceful SIGTERM)", fun() ->
        ok = erlkoenig_core:stop(Pid),
        io:format("    Container gestoppt~n"),
        ok
    end),

    test_helper:step("Verify state=stopped", fun() ->
        Info = erlkoenig_core:inspect(Pid),
        case maps:get(state, Info) of
            stopped ->
                io:format("    state=stopped~n"),
                ok;
            Other ->
                {error, {expected_stopped, Other}}
        end
    end),

    %% Spawn another, let it exit naturally
    test_helper:step("Natural exit (crasher, 2s countdown)", fun() ->
        {ok, P2} = erlkoenig_core:spawn(test_helper:demo("crasher"),
            #{ip => {10,0,0,11}, args => [<<"2">>]}),
        wait_for_state(P2, stopped, 10)
    end),

    io:format("~n=== Test 01 bestanden ===~n~n"),
    halt(0).

wait_for_state(_Pid, _Target, 0) -> {error, timeout};
wait_for_state(Pid, Target, N) ->
    try erlkoenig_core:inspect(Pid) of
        Info ->
            case maps:get(state, Info) of
                Target ->
                    io:format("    state=~p~n", [Target]),
                    ok;
                _ ->
                    timer:sleep(500),
                    wait_for_state(Pid, Target, N - 1)
            end
    catch _:_ ->
        timer:sleep(500),
        wait_for_state(Pid, Target, N - 1)
    end.
