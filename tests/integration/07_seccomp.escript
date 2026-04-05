#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 07: Seccomp Syscall Filtering
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 07: Seccomp Syscall Filtering ===~n~n"),
    test_helper:boot(),

    %% fork() should be blocked by strict seccomp
    test_helper:step("fork() mit seccomp=strict -> SIGSYS", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("syscall_fork"),
            #{ip => {10,0,0,10}, seccomp => strict}),
        wait_for_stopped(P, 10),
        io:format("    fork() blocked by seccomp~n"),
        ok
    end),

    %% mount() should be blocked
    test_helper:step("mount() mit seccomp=default -> SIGSYS", fun() ->
        {ok, P2} = erlkoenig:spawn(test_helper:demo("syscall_mount"),
            #{ip => {10,0,0,11}, seccomp => default}),
        wait_for_stopped(P2, 10),
        io:format("    mount() blocked by seccomp~n"),
        ok
    end),

    %% echo_server should work fine with default seccomp
    test_helper:step("echo_server mit seccomp=default -> funktioniert", fun() ->
        {ok, P3} = erlkoenig:spawn(test_helper:demo("echo_server"),
            #{ip => {10,0,0,12}, args => [<<"7777">>], seccomp => default}),
        timer:sleep(1000),
        Result = test_helper:echo_test({10,0,0,12}, 7777, <<"Seccomp OK!">>),
        erlkoenig:stop(P3),
        timer:sleep(300),
        Result
    end),

    io:format("~n=== Test 07 bestanden ===~n~n"),
    halt(0).

wait_for_stopped(_Pid, 0) -> {error, timeout};
wait_for_stopped(Pid, N) ->
    try erlkoenig:inspect(Pid) of
        #{state := S} when S =:= stopped; S =:= failed -> ok;
        _ -> timer:sleep(500), wait_for_stopped(Pid, N - 1)
    catch _:_ -> timer:sleep(500), wait_for_stopped(Pid, N - 1)
    end.
