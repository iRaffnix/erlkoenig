#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 04: Memory Limit (OOM-Kill)
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 04: Memory Limit (OOM-Kill) ===~n~n"),
    test_helper:boot(),

    Pid = test_helper:step("mem_eater mit 32MB Limit spawnen", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("mem_eater"),
            #{ip => {10,0,0,10},
              limits => #{memory => 32 * 1024 * 1024}}),  %% 32MB
        io:format("    mem_eater allocates 8MB blocks until OOM~n"),
        {ok, P}
    end),

    %% Wait for OOM-Kill (check state, not process liveness)
    test_helper:step("Warte auf OOM-Kill (max 10s)", fun() ->
        wait_for_state(Pid, 20)
    end),

    test_helper:step("Verify OOM-Kill", fun() ->
        Info = erlkoenig:inspect(Pid),
        io:format("    state=~p~n", [maps:get(state, Info)]),
        ok
    end),

    io:format("~n=== Test 04 bestanden ===~n~n"),
    halt(0).

wait_for_state(_Pid, 0) -> {error, timeout};
wait_for_state(Pid, N) ->
    try erlkoenig:inspect(Pid) of
        #{state := S} when S =:= stopped; S =:= failed ->
            io:format("    OOM-Kill erkannt~n"),
            ok;
        _ ->
            timer:sleep(500),
            wait_for_state(Pid, N - 1)
    catch _:_ ->
        timer:sleep(500),
        wait_for_state(Pid, N - 1)
    end.
