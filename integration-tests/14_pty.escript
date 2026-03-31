#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% pty_test.escript - PTY and stdin integration test.
%%
%% Tests two modes:
%%   1. Pipe mode: CMD_STDIN writes to container stdin pipe
%%   2. PTY mode:  CMD_STDIN writes to PTY, CMD_RESIZE changes terminal size
%%
%% Requires: unprivileged user namespaces (kernel.unprivileged_userns_clone=1)
%% Usage:    escript test/pty_test.escript

-define(TIMEOUT, 10000).
-define(SPAWN_FLAG_PTY, 16#01).

main(_Args) ->
    ScriptDir = filename:dirname(escript:script_name()),
    ProjectDir = filename:dirname(ScriptDir),
    RtBin = find_rt(ProjectDir),
    TestBin = find_demo(ProjectDir, "stdin_echo"),

    io:format("=== PTY / Stdin Test ===~n"),
    io:format("Runtime:     ~s~n", [RtBin]),
    io:format("Test binary: ~s~n", [TestBin]),

    ok = assert_file_exists(RtBin),
    ok = assert_file_exists(TestBin),

    ok = load_proto(ProjectDir),

    %% Test 1: Pipe mode (stdin pipe, no PTY)
    io:format("~n--- Test 1: Pipe Mode (CMD_STDIN) ---~n"),
    test_pipe_mode(RtBin, TestBin),

    %% Test 2: PTY mode
    io:format("~n--- Test 2: PTY Mode ---~n"),
    test_pty_mode(RtBin, TestBin),

    io:format("~n=== ALL PTY TESTS PASSED ===~n"),
    halt(0).

%% =====================================================================
%% Test 1: Pipe mode — send input via CMD_STDIN, verify echo
%% =====================================================================

test_pipe_mode(RtBin, TestBin) ->
    Port = open_rt(RtBin),

    %% Spawn without PTY flag (flags=0)
    BinPath = list_to_binary(TestBin),
    port_command(Port, erlkoenig_proto:encode_cmd_spawn(
        BinPath, [], [], 0, 0, 0, 0, 0, 0, 0)),

    {ok, reply_container_pid, _} = recv(Port),
    io:format("  Container spawned (pipe mode)~n"),

    port_command(Port, erlkoenig_proto:encode_cmd_go()),
    {ok, reply_ok, _} = recv(Port),
    io:format("  GO acknowledged~n"),

    %% Wait for "stdin_echo: ready"
    ok = wait_for_output(Port, <<"stdin_echo: ready">>, 5000),
    io:format("  stdin_echo ready~n"),

    %% Send input via CMD_STDIN
    port_command(Port, erlkoenig_proto:encode_cmd_stdin(<<"hello pipe\n">>)),
    timer:sleep(200),

    %% Verify echo
    ok = wait_for_output(Port, <<"echo: hello pipe">>, 5000),
    io:format("  Pipe echo verified~n"),

    %% Kill container
    port_command(Port, erlkoenig_proto:encode_cmd_kill(9)),
    drain_until_exit(Port),
    port_close(Port),
    io:format("  Pipe mode: OK~n").

%% =====================================================================
%% Test 2: PTY mode — spawn with PTY flag, verify echo + resize
%% =====================================================================

test_pty_mode(RtBin, TestBin) ->
    Port = open_rt(RtBin),

    %% Spawn WITH PTY flag
    BinPath = list_to_binary(TestBin),
    port_command(Port, erlkoenig_proto:encode_cmd_spawn(
        BinPath, [], [], 0, 0, 0, 0, 0, 0, ?SPAWN_FLAG_PTY)),

    {ok, reply_container_pid, _} = recv(Port),
    io:format("  Container spawned (PTY mode)~n"),

    port_command(Port, erlkoenig_proto:encode_cmd_go()),
    {ok, reply_ok, _} = recv(Port),
    io:format("  GO acknowledged~n"),

    %% Wait for "stdin_echo: ready"
    ok = wait_for_output(Port, <<"stdin_echo: ready">>, 5000),
    io:format("  stdin_echo ready (via PTY)~n"),

    %% Send input via CMD_STDIN (goes to PTY master)
    port_command(Port, erlkoenig_proto:encode_cmd_stdin(<<"hello pty\n">>)),
    timer:sleep(200),

    %% Verify echo output from PTY
    ok = wait_for_output(Port, <<"echo: hello pty">>, 5000),
    io:format("  PTY echo verified~n"),

    %% Test CMD_RESIZE (skip any PTY stdout that arrives before reply_ok)
    port_command(Port, erlkoenig_proto:encode_cmd_resize(40, 120)),
    {ok, reply_ok, _} = recv_skip_stdout(Port),
    io:format("  RESIZE 40x120: OK~n"),

    %% Kill container
    port_command(Port, erlkoenig_proto:encode_cmd_kill(9)),
    drain_until_exit(Port),
    port_close(Port),
    io:format("  PTY mode: OK~n").

%% =====================================================================
%% Helpers
%% =====================================================================

open_rt(RtBin) ->
    Port = open_port({spawn_executable, RtBin},
                     [{packet, 4}, binary, exit_status, use_stdio]),
    port_command(Port, erlkoenig_proto:encode_handshake()),
    {ok, HsReply} = recv_raw(Port),
    ok = erlkoenig_proto:check_handshake_reply(HsReply),
    Port.

recv(Port) ->
    receive
        {Port, {data, Data}} ->
            erlkoenig_proto:decode(Data);
        {Port, {exit_status, Status}} ->
            io:format("ERROR: erlkoenig_rt exited with status ~p~n", [Status]),
            halt(1)
    after ?TIMEOUT ->
        io:format("ERROR: timeout (~p ms)~n", [?TIMEOUT]),
        halt(1)
    end.

recv_skip_stdout(Port) ->
    case recv(Port) of
        {ok, reply_stdout, _} -> recv_skip_stdout(Port);
        Other                 -> Other
    end.

recv_raw(Port) ->
    receive
        {Port, {data, Data}} ->
            {ok, Data};
        {Port, {exit_status, Status}} ->
            {error, {port_exited, Status}}
    after ?TIMEOUT ->
        {error, timeout}
    end.

%% Wait for a specific substring in stdout output
wait_for_output(Port, Pattern, Timeout) ->
    wait_for_output(Port, Pattern, Timeout, <<>>).

wait_for_output(_Port, _Pattern, Timeout, _Acc) when Timeout =< 0 ->
    io:format("  TIMEOUT waiting for output pattern~n"),
    {error, timeout};
wait_for_output(Port, Pattern, Timeout, Acc) ->
    T0 = erlang:monotonic_time(millisecond),
    receive
        {Port, {data, Data}} ->
            case erlkoenig_proto:decode(Data) of
                {ok, reply_stdout, #{data := Chunk}} ->
                    NewAcc = <<Acc/binary, Chunk/binary>>,
                    case binary:match(NewAcc, Pattern) of
                        nomatch ->
                            Elapsed = erlang:monotonic_time(millisecond) - T0,
                            wait_for_output(Port, Pattern,
                                          Timeout - Elapsed, NewAcc);
                        _ ->
                            ok
                    end;
                {ok, reply_stderr, _} ->
                    Elapsed = erlang:monotonic_time(millisecond) - T0,
                    wait_for_output(Port, Pattern, Timeout - Elapsed, Acc);
                {ok, reply_exited, Info} ->
                    io:format("  Container exited unexpectedly: ~p~n", [Info]),
                    {error, exited};
                Other ->
                    io:format("  Unexpected during wait: ~p~n", [Other]),
                    Elapsed = erlang:monotonic_time(millisecond) - T0,
                    wait_for_output(Port, Pattern, Timeout - Elapsed, Acc)
            end;
        {Port, {exit_status, Status}} ->
            io:format("ERROR: erlkoenig_rt exited with status ~p~n", [Status]),
            halt(1)
    after Timeout ->
        io:format("  TIMEOUT waiting for ~s (got: ~s)~n",
                  [Pattern, Acc]),
        {error, timeout}
    end.

drain_until_exit(Port) ->
    receive
        {Port, {data, Data}} ->
            case erlkoenig_proto:decode(Data) of
                {ok, reply_exited, _} -> ok;
                _ -> drain_until_exit(Port)
            end;
        {Port, {exit_status, _}} -> ok
    after 5000 -> ok
    end.

assert_file_exists(Path) ->
    case filelib:is_regular(Path) of
        true -> ok;
        false ->
            io:format("ERROR: file not found: ~s~n", [Path]),
            halt(1)
    end.

%% Find erlkoenig_rt binary.
%% Search order: $ERLKOENIG_RT_PATH -> /opt/erlkoenig/rt -> build/release
find_rt(ProjectDir) ->
    case os:getenv("ERLKOENIG_RT_PATH") of
        false -> find_rt_installed(ProjectDir);
        Path  -> Path
    end.

find_rt_installed(ProjectDir) ->
    Installed = "/opt/erlkoenig/rt/erlkoenig_rt",
    case filelib:is_regular(Installed) of
        true  -> Installed;
        false ->
            filename:absname(
                filename:join(ProjectDir, "build/release/erlkoenig_rt"))
    end.

%% Find a demo binary by short name (e.g. "stdin_echo").
%% Search order: $ERLKOENIG_DEMO_DIR -> /opt/erlkoenig/rt/demo -> build/release/demo
find_demo(ProjectDir, Name) ->
    BinName = "test-erlkoenig-" ++ Name,
    case os:getenv("ERLKOENIG_DEMO_DIR") of
        false -> find_demo_installed(ProjectDir, BinName);
        Dir   -> filename:join(Dir, BinName)
    end.

find_demo_installed(ProjectDir, BinName) ->
    Installed = filename:join("/opt/erlkoenig/rt/demo", BinName),
    case filelib:is_regular(Installed) of
        true  -> Installed;
        false ->
            filename:absname(
                filename:join([ProjectDir, "build/release/demo", BinName]))
    end.

%% Load erlkoenig_proto module.
load_proto(ProjectDir) ->
    case code:is_loaded(erlkoenig_proto) of
        {file, _} -> ok;
        false     -> load_proto_search(ProjectDir)
    end.

load_proto_search(ProjectDir) ->
    ReleaseDirs = filelib:wildcard("/opt/erlkoenig/lib/erlkoenig-*/ebin"),
    BuildDir = filename:join(ProjectDir, "_build/default/lib/erlkoenig/ebin"),
    Candidates = ReleaseDirs ++ [BuildDir],
    case lists:filter(fun filelib:is_dir/1, Candidates) of
        [Dir | _] ->
            code:add_pathz(Dir),
            case code:ensure_loaded(erlkoenig_proto) of
                {module, erlkoenig_proto} -> ok;
                {error, R} ->
                    io:format("ERROR: cannot load erlkoenig_proto from ~s: ~p~n",
                              [Dir, R]),
                    halt(1)
            end;
        [] ->
            io:format("ERROR: erlkoenig_proto ebin not found~n"),
            halt(1)
    end.
