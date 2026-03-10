#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 06: Restart Policy (auto-restart with backoff)
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 06: Restart Policy ===~n~n"),
    test_helper:boot(),

    Pid = test_helper:step("crasher mit restart=on_failure,3 spawnen", fun() ->
        {ok, P} = erlkoenig_core:spawn(test_helper:demo("crasher"),
            #{ip => {10,0,0,10},
              args => [<<"1">>],             %% exits after 1 second
              restart => {on_failure, 3}}),   %% max 3 restarts
        io:format("    crasher exits after 1s, will restart up to 3x~n"),
        {ok, P}
    end),

    %% Watch restart count increase
    test_helper:step("Warte auf Restarts (max 20s)", fun() ->
        watch_restarts(Pid, 0, 40)
    end),

    %% Verify restart count
    test_helper:step("Restart-Count pruefen", fun() ->
        case erlang:is_process_alive(Pid) of
            true ->
                Info = erlkoenig_core:inspect(Pid),
                Count = maps:get(restart_count, Info, 0),
                io:format("    restart_count=~p~n", [Count]),
                case Count >= 1 of
                    true -> ok;
                    false -> {error, {no_restarts, Count}}
                end;
            false ->
                %% Already exhausted all restarts — also OK
                io:format("    All restarts exhausted, container stopped~n"),
                ok
        end
    end),

    %% Wait for final stop
    timer:sleep(5000),
    test_helper:step("Container endgueltig gestoppt", fun() ->
        case erlang:is_process_alive(Pid) of
            false ->
                io:format("    Alle Restarts verbraucht~n"),
                ok;
            true ->
                erlkoenig_core:stop(Pid),
                io:format("    Manuell gestoppt (noch in Backoff)~n"),
                ok
        end
    end),

    io:format("~n=== Test 06 bestanden ===~n~n"),
    halt(0).

watch_restarts(_Pid, _, 0) -> ok;  %% timeout is ok, we check count later
watch_restarts(Pid, Last, N) ->
    case erlang:is_process_alive(Pid) of
        false -> ok;
        true ->
            try erlkoenig_core:inspect(Pid) of
                #{restart_count := Count} when Count > Last ->
                    io:format("    restart #~p~n", [Count]),
                    case Count >= 3 of
                        true -> ok;
                        false ->
                            timer:sleep(500),
                            watch_restarts(Pid, Count, N - 1)
                    end;
                _ ->
                    timer:sleep(500),
                    watch_restarts(Pid, Last, N - 1)
            catch _:_ ->
                timer:sleep(500),
                watch_restarts(Pid, Last, N - 1)
            end
    end.
