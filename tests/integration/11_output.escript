#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 11: Output Capture (stdout/stderr forwarding)
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 11: Output Capture ===~n~n"),
    test_helper:boot(),

    Self = self(),
    Pid = test_helper:step("hello_output mit output=self() spawnen", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("hello_output"),
            #{ip => {10,0,0,10}, output => Self}),
        io:format("    stdout/stderr -> Erlang process ~p~n", [Self]),
        {ok, P}
    end),

    %% Collect output messages
    test_helper:step("stdout/stderr Nachrichten empfangen (max 5s)", fun() ->
        collect_output(5000)
    end),

    %% Verify container exited
    timer:sleep(1000),
    test_helper:step("Container beendet", fun() ->
        case erlang:is_process_alive(Pid) of
            false -> ok;
            true ->
                erlkoenig:stop(Pid),
                ok
        end
    end),

    io:format("~n=== Test 11 bestanden ===~n~n"),
    halt(0).

collect_output(Timeout) ->
    collect_output(Timeout, 0).

collect_output(_, Count) when Count >= 1 ->
    %% Got at least one message
    drain_remaining(),
    io:format("    ~p Output-Nachrichten empfangen~n", [Count]),
    ok;
collect_output(Timeout, Count) when Timeout =< 0 ->
    case Count of
        0 -> {error, no_output_received};
        _ -> ok
    end;
collect_output(Timeout, Count) ->
    Start = erlang:monotonic_time(millisecond),
    receive
        {container_stdout, _Pid, _Id, Data} ->
            io:format("    [stdout] ~s", [Data]),
            Elapsed = erlang:monotonic_time(millisecond) - Start,
            collect_output(Timeout - Elapsed, Count + 1);
        {container_stderr, _Pid, _Id, Data} ->
            io:format("    [stderr] ~s", [Data]),
            Elapsed = erlang:monotonic_time(millisecond) - Start,
            collect_output(Timeout - Elapsed, Count + 1)
    after Timeout ->
        case Count of
            0 -> {error, no_output_received};
            _ -> ok
        end
    end.

drain_remaining() ->
    receive
        {container_stdout, _, _, Data} ->
            io:format("    [stdout] ~s", [Data]),
            drain_remaining();
        {container_stderr, _, _, Data} ->
            io:format("    [stderr] ~s", [Data]),
            drain_remaining()
    after 200 -> ok
    end.
