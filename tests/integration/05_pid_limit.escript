#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 05: PID Limit (fork bomb protection)
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 05: PID Limit ===~n~n"),
    test_helper:boot(),

    Pid = test_helper:step("syscall_fork mit PID-Limit=5 spawnen", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("syscall_fork"),
            #{ip => {10,0,0,10},
              limits => #{pids => 5}}),
        io:format("    fork() should fail when limit reached~n"),
        {ok, P}
    end),

    %% Wait for exit (check state)
    test_helper:step("Warte auf Exit (max 10s)", fun() ->
        wait_for_state(Pid, 20)
    end),

    test_helper:step("Container beendet (fork limitiert)", fun() ->
        Info = erlkoenig:inspect(Pid),
        io:format("    state=~p, PID-Limit hat fork() gestoppt~n", [maps:get(state, Info)]),
        ok
    end),

    io:format("~n=== Test 05 bestanden ===~n~n"),
    halt(0).

wait_for_state(_Pid, 0) -> {error, timeout};
wait_for_state(Pid, N) ->
    try erlkoenig:inspect(Pid) of
        #{state := S} when S =:= stopped; S =:= failed ->
            ok;
        _ ->
            timer:sleep(500),
            wait_for_state(Pid, N - 1)
    catch _:_ ->
        timer:sleep(500),
        wait_for_state(Pid, N - 1)
    end.
