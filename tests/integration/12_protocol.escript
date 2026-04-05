#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% hello_container_test.escript - Hello Container milestone test.
%%
%% Exercises the full SPAWN -> CONTAINER_PID -> GO -> EXITED sequence
%% against erlkoenig_rt via the {packet,4} binary protocol.
%%
%% Requires: unprivileged user namespaces (kernel.unprivileged_userns_clone=1)
%% Usage:    escript test/hello_container_test.escript
%%

-define(TIMEOUT, 10000).

main(_Args) ->
    ScriptDir = filename:dirname(escript:script_name()),
    ProjectDir = filename:dirname(ScriptDir),
    RtBin = find_rt(ProjectDir),
    TestBin = find_demo(ProjectDir, "hello_output"),

    io:format("=== Hello Container Test ===~n"),
    io:format("Runtime:     ~s~n", [RtBin]),
    io:format("Test binary: ~s~n", [TestBin]),

    ok = assert_file_exists(RtBin),
    ok = assert_file_exists(TestBin),

    ok = load_proto(ProjectDir),

    %% Step 1: Open port
    io:format("~n--- Step 1: Open port ---~n"),
    Port = open_port({spawn_executable, RtBin},
                     [{packet, 4}, binary, exit_status, use_stdio]),
    io:format("Port opened: ~p~n", [Port]),

    %% Step 1b: Protocol handshake
    io:format("~n--- Step 1b: Handshake ---~n"),
    port_command(Port, erlkoenig_proto:encode_handshake()),
    case recv_raw(Port) of
        {ok, HsReply} ->
            case erlkoenig_proto:check_handshake_reply(HsReply) of
                ok ->
                    io:format("Handshake OK (protocol v~p)~n",
                              [erlkoenig_proto:protocol_version()]);
                {error, HsErr} ->
                    io:format("Handshake FAILED: ~p~n", [HsErr]),
                    port_close(Port),
                    halt(1)
            end;
        {error, HsErr} ->
            io:format("Handshake FAILED: ~p~n", [HsErr]),
            port_close(Port),
            halt(1)
    end,

    %% Step 2: Send SPAWN
    io:format("~n--- Step 2: SPAWN ---~n"),
    BinPath = list_to_binary(TestBin),
    port_command(Port, erlkoenig_proto:encode_cmd_spawn(BinPath, [], [], 0, 0, 0)),

    %% Step 3: Receive reply_container_pid
    io:format("~n--- Step 3: Waiting for reply ---~n"),
    case recv(Port) of
        {ok, reply_container_pid, #{child_pid := Pid, netns_path := Ns}} ->
            io:format("Container PID: ~p  netns: ~s~n", [Pid, Ns]);
        {ok, reply_error, #{code := Code, message := Msg}} ->
            io:format("SPAWN failed: ~p ~s~n", [Code, Msg]),
            port_close(Port),
            halt(2)
    end,

    %% Step 4: Send GO (uid_map/gid_map written by C runtime after clone)
    io:format("~n--- Step 4: GO ---~n"),
    port_command(Port, erlkoenig_proto:encode_cmd_go()),

    %% Step 5: Collect reply_ok and reply_exited (order may vary)
    %% The child may exit before or after we receive reply_ok.
    io:format("~n--- Step 5: Waiting for reply_ok + reply_exited ---~n"),
    {GotOk, GotExited} = collect_ok_and_exited(Port, false, undefined),

    case {GotOk, GotExited} of
        {true, #{exit_code := 0}} ->
            io:format("~n=== SUCCESS ===~n"),
            io:format("Container exited cleanly (exit_code=0)~n"),
            port_close(Port),
            halt(0);
        {true, #{exit_code := EC, term_signal := Sig}} ->
            io:format("~n=== FAILURE ===~n"),
            io:format("Container exited with code=~p signal=~p~n", [EC, Sig]),
            port_close(Port),
            halt(1);
        _ ->
            io:format("~n=== FAILURE ===~n"),
            io:format("Unexpected result: ok=~p exited=~p~n",
                      [GotOk, GotExited]),
            port_close(Port),
            halt(1)
    end.

%% Collect both reply_ok and reply_exited in any order.
%% The child may exit very fast, so reply_exited can arrive
%% before or after reply_ok.
collect_ok_and_exited(_Port, true, ExitInfo) when ExitInfo =/= undefined ->
    {true, ExitInfo};
collect_ok_and_exited(Port, GotOk, ExitInfo) ->
    case recv(Port) of
        {ok, reply_ok, _} ->
            io:format("  GO acknowledged~n"),
            collect_ok_and_exited(Port, true, ExitInfo);
        {ok, reply_exited, Info} ->
            io:format("  Child exited: ~p~n", [Info]),
            collect_ok_and_exited(Port, GotOk, Info);
        {ok, reply_stdout, #{data := Data}} ->
            io:format("  stdout: ~s", [Data]),
            collect_ok_and_exited(Port, GotOk, ExitInfo);
        {ok, reply_stderr, #{data := Data}} ->
            io:format("  stderr: ~s", [Data]),
            collect_ok_and_exited(Port, GotOk, ExitInfo);
        Other ->
            io:format("  Unexpected reply: ~p~n", [Other]),
            {GotOk, ExitInfo}
    end.

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

recv_raw(Port) ->
    receive
        {Port, {data, Data}} ->
            {ok, Data};
        {Port, {exit_status, Status}} ->
            {error, {port_exited, Status}}
    after ?TIMEOUT ->
        {error, timeout}
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

%% Find a demo binary by short name (e.g. "hello_output").
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
%% Search order: already loaded -> OTP release lib -> _build/default
load_proto(ProjectDir) ->
    case code:is_loaded(erlkoenig_proto) of
        {file, _} -> ok;
        false     -> load_proto_search(ProjectDir)
    end.

load_proto_search(ProjectDir) ->
    %% OTP release: /opt/erlkoenig/lib/erlkoenig-*/ebin
    ReleaseDirs = filelib:wildcard("/opt/erlkoenig/lib/erlkoenig-*/ebin"),
    %% Local build: _build/default/lib/erlkoenig/ebin
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
            io:format("ERROR: erlkoenig_proto ebin not found~n"
                      "       run 'rebar3 compile' or install OTP release~n"),
            halt(1)
    end.
