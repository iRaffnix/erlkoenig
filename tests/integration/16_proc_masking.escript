#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% 16_proc_masking.escript - Verify /proc paths are masked inside container.
%%
%% Spawns a real container running proc_check, which probes all OCI-standard
%% masked paths and reports MASKED/OPEN/SKIP for each.
%%
%% Usage: sudo escript integration-tests/16_proc_masking.escript

-define(TIMEOUT, 10000).

main(_Args) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    ProjectDir = test_helper:project_root(),
    RtBin = test_helper:rt_binary(),
    TestBin = binary_to_list(test_helper:demo("proc_check")),

    io:format("=== /proc Masking Test ===~n"),
    io:format("Runtime:     ~s~n", [RtBin]),
    io:format("Test binary: ~s~n", [TestBin]),

    ok = assert_file_exists(RtBin),
    ok = assert_file_exists(TestBin),
    ok = load_proto(ProjectDir),

    Port = open_rt(RtBin),

    %% Spawn container with proc_check binary
    BinPath = list_to_binary(TestBin),
    port_command(Port, erlkoenig_proto:encode_cmd_spawn(
        BinPath, [], [], 0, 0, 0, 0, 0, 0, 0)),

    {ok, reply_container_pid, _} = recv(Port),
    io:format("  Container spawned~n"),

    port_command(Port, erlkoenig_proto:encode_cmd_go()),
    {ok, reply_ok, _} = recv(Port),
    io:format("  GO acknowledged~n"),

    %% Collect all output until DONE
    Output = collect_output(Port, <<>>),
    io:format("~n--- proc_check output ---~n~s~n", [Output]),

    %% Parse and verify
    Lines = binary:split(Output, <<"\n">>, [global, trim_all]),
    verify_lines(Lines),

    drain_until_exit(Port),
    port_close(Port),

    io:format("~n=== PROC MASKING TEST PASSED ===~n"),
    halt(0).

%% =====================================================================
%% Verification
%% =====================================================================

verify_lines([]) ->
    ok;
verify_lines([Line | Rest]) ->
    case Line of
        <<"MASKED ", Path/binary>> ->
            io:format("  OK: ~s is masked~n", [Path]),
            verify_lines(Rest);
        <<"SKIP ", Path/binary>> ->
            io:format("  SKIP: ~s not present on this kernel~n", [Path]),
            verify_lines(Rest);
        <<"DONE">> ->
            io:format("  proc_check completed~n"),
            verify_lines(Rest);
        <<"OPEN ", Path/binary>> ->
            io:format("  FAIL: ~s is NOT masked!~n", [Path]),
            halt(1);
        Other ->
            io:format("  WARN: unexpected line: ~s~n", [Other]),
            verify_lines(Rest)
    end.

%% =====================================================================
%% Output collection — read stdout until we see "DONE"
%% =====================================================================

collect_output(Port, Acc) ->
    receive
        {Port, {data, Data}} ->
            case erlkoenig_proto:decode(Data) of
                {ok, reply_stdout, #{data := Chunk}} ->
                    NewAcc = <<Acc/binary, Chunk/binary>>,
                    case binary:match(NewAcc, <<"DONE">>) of
                        nomatch -> collect_output(Port, NewAcc);
                        _       -> NewAcc
                    end;
                {ok, reply_stderr, #{data := Chunk}} ->
                    io:format("  stderr: ~s", [Chunk]),
                    collect_output(Port, Acc);
                {ok, reply_exited, Info} ->
                    io:format("  Container exited early: ~p~n", [Info]),
                    Acc;
                _ ->
                    collect_output(Port, Acc)
            end;
        {Port, {exit_status, Status}} ->
            io:format("ERROR: erlkoenig_rt exited with status ~p~n", [Status]),
            halt(1)
    after ?TIMEOUT ->
        io:format("ERROR: timeout waiting for proc_check output~n"),
        io:format("  collected so far: ~s~n", [Acc]),
        halt(1)
    end.

%% =====================================================================
%% Helpers (same pattern as other integration tests)
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

recv_raw(Port) ->
    receive
        {Port, {data, Data}} ->
            {ok, Data};
        {Port, {exit_status, Status}} ->
            {error, {port_exited, Status}}
    after ?TIMEOUT ->
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
