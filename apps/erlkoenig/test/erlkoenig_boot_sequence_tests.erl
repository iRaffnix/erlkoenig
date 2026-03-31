%%%-------------------------------------------------------------------
%%% @doc Unit tests for the crash recovery boot sequence.
%%%
%%% Tests the individual module interaction during boot:
%%% 1. erlkoenig_node_state starts and opens DETS
%%% 2. erlkoenig_recovery reads DETS and cleans up dead containers
%%%
%%% Does NOT start the full application (would need root for zones,
%%% bridges, etc.). Instead tests the boot-relevant modules in
%%% isolation.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_boot_sequence_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%%====================================================================
%% Helpers
%%====================================================================

tmp_dir() ->
    "/tmp/erlkoenig_boot_test_" ++
    integer_to_list(erlang:unique_integer([positive])).

%%====================================================================
%% Tests
%%====================================================================

clean_boot_test_() ->
    {"fresh DETS -> recovery returns empty",
     fun() ->
         TmpDir = tmp_dir(),
         ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
         DetsPath = filename:join(TmpDir, "node.dets"),

         %% Step 1: Start DETS state
         {ok, Pid} = erlkoenig_node_state:start_link(DetsPath),

         %% Step 2: Recovery on empty state
         {ok, Results} = erlkoenig_recovery:recover(),
         ?assertEqual([], Results),

         %% Cleanup
         gen_server:stop(Pid),
         os:cmd("rm -rf " ++ TmpDir)
     end}.

boot_with_stale_dets_test_() ->
    {"pre-populated DETS with dead containers -> recovery cleans up",
     fun() ->
         TmpDir = tmp_dir(),
         ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
         DetsPath = filename:join(TmpDir, "node.dets"),

         %% Pre-populate DETS with stale entries directly
         {ok, Tab} = dets:open_file(boot_test_tab,
                         [{file, DetsPath}, {type, set}]),
         ok = dets:insert(Tab, {<<"stale-web">>,
                  #{os_pid => 999999999,
                    socket_path => <<"/tmp/stale.sock">>,
                    comm_mode => socket}}),
         ok = dets:insert(Tab, {<<"stale-db">>,
                  #{os_pid => 999999998,
                    comm_mode => port}}),
         ok = dets:sync(Tab),
         ok = dets:close(Tab),

         %% Now simulate boot sequence
         {ok, Pid} = erlkoenig_node_state:start_link(DetsPath),

         %% Verify entries are there before recovery
         All = erlkoenig_node_state:all_containers(),
         ?assertEqual(2, length(All)),

         %% Run recovery
         {ok, Results} = erlkoenig_recovery:recover(),
         ?assertEqual(2, length(Results)),

         %% Both should be dead
         ResultMap = maps:from_list(Results),
         ?assertEqual(dead, maps:get(<<"stale-web">>, ResultMap)),
         ?assertEqual(dead, maps:get(<<"stale-db">>, ResultMap)),

         %% DETS should be clean now
         ?assertEqual([], erlkoenig_node_state:all_containers()),

         %% Cleanup
         gen_server:stop(Pid),
         os:cmd("rm -rf " ++ TmpDir)
     end}.

boot_recovery_then_register_test_() ->
    {"after recovery, new containers can be registered normally",
     fun() ->
         TmpDir = tmp_dir(),
         ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
         DetsPath = filename:join(TmpDir, "node.dets"),

         %% Pre-populate with one dead container
         {ok, Tab} = dets:open_file(boot_reg_tab,
                         [{file, DetsPath}, {type, set}]),
         ok = dets:insert(Tab, {<<"old">>,
                  #{os_pid => 999999999, comm_mode => port}}),
         ok = dets:sync(Tab),
         ok = dets:close(Tab),

         %% Boot
         {ok, Pid} = erlkoenig_node_state:start_link(DetsPath),
         {ok, _Results} = erlkoenig_recovery:recover(),

         %% Now register a new container — must work fine
         ok = erlkoenig_node_state:register_container(<<"new-web">>,
                  #{os_pid => 42, comm_mode => socket,
                    socket_path => <<"/run/erlkoenig/containers/new-web.sock">>}),
         {ok, Info} = erlkoenig_node_state:get_container(<<"new-web">>),
         ?assertEqual(42, maps:get(os_pid, Info)),

         %% Only the new one remains
         ?assertEqual(1, length(erlkoenig_node_state:all_containers())),

         gen_server:stop(Pid),
         os:cmd("rm -rf " ++ TmpDir)
     end}.

double_recovery_idempotent_test_() ->
    {"running recovery twice is safe",
     fun() ->
         TmpDir = tmp_dir(),
         ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
         DetsPath = filename:join(TmpDir, "node.dets"),

         {ok, Pid} = erlkoenig_node_state:start_link(DetsPath),
         ok = erlkoenig_node_state:register_container(<<"ct">>,
                  #{os_pid => 999999999, comm_mode => port}),

         {ok, R1} = erlkoenig_recovery:recover(),
         ?assertEqual(1, length(R1)),

         %% Second recovery: nothing left to recover
         {ok, R2} = erlkoenig_recovery:recover(),
         ?assertEqual(0, length(R2)),

         gen_server:stop(Pid),
         os:cmd("rm -rf " ++ TmpDir)
     end}.
