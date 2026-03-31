%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_recovery (boot-time container recovery).
%%%
%%% Tests the recovery logic WITHOUT requiring root or actual containers.
%%% Uses real OS processes (sleep) to test is_process_alive_os, and
%%% fake PIDs (999999999) to test dead-process detection.
%%%
%%% Each test starts its own erlkoenig_node_state with a temporary DETS
%%% file and cleans up after itself.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_recovery_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%%====================================================================
%% Helpers
%%====================================================================

setup() ->
    TmpDir = "/tmp/erlkoenig_recovery_test_" ++
             integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
    DetsPath = filename:join(TmpDir, "recovery.dets"),
    {ok, Pid} = erlkoenig_node_state:start_link(DetsPath),
    {Pid, TmpDir, DetsPath}.

cleanup({Pid, TmpDir, _DetsPath}) ->
    unlink(Pid),
    gen_server:stop(Pid),
    os:cmd("rm -rf " ++ TmpDir).

%% Start a real OS process we can detect via /proc
start_alive_process() ->
    Port = open_port({spawn, "sleep 3600"}, []),
    {os_pid, OsPid} = erlang:port_info(Port, os_pid),
    {Port, OsPid}.

stop_alive_process({Port, OsPid}) ->
    catch port_close(Port),
    os:cmd("kill " ++ integer_to_list(OsPid) ++ " 2>/dev/null"),
    ok.

%%====================================================================
%% Test generator
%%====================================================================

recovery_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun recover_empty/1,
      fun recover_dead_process/1,
      fun recover_port_mode/1,
      fun recover_cleanup_on_dead/1,
      fun recover_no_comm_mode/1,
      fun recover_multiple_mixed/1,
      fun recovery_results_format/1,
      fun cleanup_dead_tries_destroy/1
     ]}.

%% Standalone tests: is_process_alive_os is not exported,
%% so we test liveness detection indirectly through recover/0.
%% The dead/alive PID tests above (recover_dead_process, recover_alive_no_socket)
%% cover the same logic end-to-end.

%%====================================================================
%% Pure function tests — migration_needed/2
%%====================================================================

migration_needed_test() ->
    %% Old path (binary from DETS) differs from new path (string from cgroup:path)
    ?assertEqual(migrate,
                 erlkoenig_recovery:migration_needed(
                     <<"/sys/fs/cgroup/erlkoenig/web-1">>,
                     "/sys/fs/cgroup/erlkoenig/containers/web-1")).

migration_not_needed_test() ->
    %% Same path — no migration needed
    ?assertEqual(ok,
                 erlkoenig_recovery:migration_needed(
                     <<"/sys/fs/cgroup/erlkoenig/containers/web-1">>,
                     "/sys/fs/cgroup/erlkoenig/containers/web-1")).

migration_needed_same_content_test() ->
    %% Same content as binary vs string — should return ok (no migration)
    Path = "/sys/fs/cgroup/erlkoenig/containers/app-42",
    ?assertEqual(ok,
                 erlkoenig_recovery:migration_needed(
                     list_to_binary(Path), Path)).

%%====================================================================
%% Individual test functions
%%====================================================================

recover_empty({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ?assertEqual({ok, []}, erlkoenig_recovery:recover())
    end.

recover_dead_process({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        %% Register container with a PID that doesn't exist
        ok = erlkoenig_node_state:register_container(<<"dead-ct">>,
                 #{os_pid => 999999999,
                   socket_path => <<"/tmp/nonexistent.sock">>,
                   comm_mode => socket}),
        {ok, Results} = erlkoenig_recovery:recover(),
        ?assertEqual(1, length(Results)),
        ?assertEqual({<<"dead-ct">>, dead}, hd(Results)),
        %% DETS entry must be cleaned up
        ?assertEqual({error, not_found},
                     erlkoenig_node_state:get_container(<<"dead-ct">>))
    end.

recover_port_mode({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        %% Port-mode containers always die on BEAM crash
        ok = erlkoenig_node_state:register_container(<<"port-ct">>,
                 #{os_pid => 12345, comm_mode => port}),
        {ok, Results} = erlkoenig_recovery:recover(),
        ?assertEqual(1, length(Results)),
        ?assertEqual({<<"port-ct">>, dead}, hd(Results)),
        %% DETS entry cleaned up
        ?assertEqual({error, not_found},
                     erlkoenig_node_state:get_container(<<"port-ct">>))
    end.

recover_cleanup_on_dead({_Pid, TmpDir, _DetsPath}) ->
    fun() ->
        %% Create a fake socket file to verify cleanup deletes it
        FakeSock = filename:join(TmpDir, "dead.sock"),
        ok = file:write_file(FakeSock, <<>>),
        ?assert(filelib:is_file(FakeSock)),

        ok = erlkoenig_node_state:register_container(<<"dead-with-sock">>,
                 #{os_pid => 999999999,
                   socket_path => list_to_binary(FakeSock),
                   comm_mode => socket}),
        {ok, _Results} = erlkoenig_recovery:recover(),
        %% Socket file should be deleted
        ?assertNot(filelib:is_file(FakeSock)),
        %% DETS entry gone
        ?assertEqual({error, not_found},
                     erlkoenig_node_state:get_container(<<"dead-with-sock">>))
    end.

recover_no_comm_mode({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        %% Container without comm_mode → treated as dead
        ok = erlkoenig_node_state:register_container(<<"no-mode">>,
                 #{os_pid => 999999999}),
        {ok, Results} = erlkoenig_recovery:recover(),
        ?assertEqual(1, length(Results)),
        ?assertEqual({<<"no-mode">>, dead}, hd(Results)),
        ?assertEqual({error, not_found},
                     erlkoenig_node_state:get_container(<<"no-mode">>))
    end.

recover_multiple_mixed({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        %% Register 3 containers: one dead socket, one port, one no comm_mode
        ok = erlkoenig_node_state:register_container(<<"dead-sock">>,
                 #{os_pid => 999999999,
                   socket_path => <<"/tmp/nonexistent.sock">>,
                   comm_mode => socket}),
        ok = erlkoenig_node_state:register_container(<<"port-ct">>,
                 #{os_pid => 999999998, comm_mode => port}),
        ok = erlkoenig_node_state:register_container(<<"no-mode">>,
                 #{os_pid => 999999997}),

        {ok, Results} = erlkoenig_recovery:recover(),
        ?assertEqual(3, length(Results)),

        %% All should be dead
        ResultMap = maps:from_list(Results),
        ?assertEqual(dead, maps:get(<<"dead-sock">>, ResultMap)),
        ?assertEqual(dead, maps:get(<<"port-ct">>, ResultMap)),
        ?assertEqual(dead, maps:get(<<"no-mode">>, ResultMap)),

        %% All DETS entries cleaned up
        ?assertEqual([], erlkoenig_node_state:all_containers())
    end.

recovery_results_format({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ok = erlkoenig_node_state:register_container(<<"ct-1">>,
                 #{os_pid => 999999999, comm_mode => port}),
        ok = erlkoenig_node_state:register_container(<<"ct-2">>,
                 #{os_pid => 999999998, comm_mode => socket,
                   socket_path => <<"/tmp/no.sock">>}),

        {ok, Results} = erlkoenig_recovery:recover(),
        %% Return format is {ok, [{Id, Status}]}
        ?assert(is_list(Results)),
        lists:foreach(fun({Id, Status}) ->
            ?assert(is_binary(Id)),
            ?assert(Status =:= recovered orelse
                    Status =:= dead orelse
                    is_tuple(Status))
        end, Results)
    end.

cleanup_dead_tries_destroy({_Pid, TmpDir, _DetsPath}) ->
    fun() ->
        %% Register a dead container with a cgroup path.
        %% cleanup_dead will try erlkoenig_cgroup:destroy(Id) via catch —
        %% since the cgroup gen_server is not running, this must not crash.
        FakeSock = filename:join(TmpDir, "cgroup_dead.sock"),
        ok = file:write_file(FakeSock, <<>>),

        ok = erlkoenig_node_state:register_container(<<"cgroup-dead">>,
                 #{os_pid => 999999999,
                   socket_path => list_to_binary(FakeSock),
                   cgroup => <<"/sys/fs/cgroup/erlkoenig/web-1">>,
                   comm_mode => socket}),
        %% recover/0 will detect the dead process and call cleanup_dead,
        %% which tries erlkoenig_cgroup:destroy(Id). The catch ensures
        %% no crash even without the gen_server running.
        {ok, Results} = erlkoenig_recovery:recover(),
        ?assertEqual(1, length(Results)),
        ?assertEqual({<<"cgroup-dead">>, dead}, hd(Results)),
        %% DETS entry cleaned up
        ?assertEqual({error, not_found},
                     erlkoenig_node_state:get_container(<<"cgroup-dead">>)),
        %% Socket file cleaned up
        ?assertNot(filelib:is_file(FakeSock))
    end.

%% Test with an ALIVE process — recovery will detect it as alive, but
%% start_recovering will fail because there's no actual socket.
%% This tests the error handling path.
recover_alive_no_socket_test_() ->
    {"alive process but no socket -> error path",
     fun() ->
         TmpDir = "/tmp/erlkoenig_recovery_alive_" ++
                  integer_to_list(erlang:unique_integer([positive])),
         ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
         DetsPath = filename:join(TmpDir, "alive.dets"),
         {ok, DPid} = erlkoenig_node_state:start_link(DetsPath),

         {Port, OsPid} = start_alive_process(),
         try
             ok = erlkoenig_node_state:register_container(<<"alive-ct">>,
                      #{os_pid => OsPid,
                        socket_path => <<"/tmp/nonexistent_for_test.sock">>,
                        comm_mode => socket}),
             %% Recovery will find the process alive, try to recover,
             %% but start_recovering will fail (no actual container).
             %% It should return {error, _} for this container, not crash.
             {ok, Results} = erlkoenig_recovery:recover(),
             ?assertEqual(1, length(Results)),
             {<<"alive-ct">>, Status} = hd(Results),
             %% Could be recovered (if start_recovering somehow works)
             %% or {error, _} if it fails. Either way, no crash.
             ?assert(Status =:= recovered orelse is_tuple(Status))
         after
             stop_alive_process({Port, OsPid}),
             gen_server:stop(DPid),
             os:cmd("rm -rf " ++ TmpDir)
         end
     end}.
