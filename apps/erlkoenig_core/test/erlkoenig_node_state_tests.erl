%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_node_state (DETS state persistence).
%%%
%%% Each test starts its own gen_server with a unique temporary DETS
%%% file and cleans up after itself. No root or network required.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_node_state_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%%====================================================================
%% Helpers
%%====================================================================

setup() ->
    TmpDir = "/tmp/erlkoenig_dets_test_" ++
             integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
    DetsPath = filename:join(TmpDir, "test_node.dets"),
    {ok, Pid} = erlkoenig_node_state:start_link(DetsPath),
    {Pid, TmpDir, DetsPath}.

cleanup({Pid, TmpDir, _DetsPath}) ->
    unlink(Pid),
    gen_server:stop(Pid),
    os:cmd("rm -rf " ++ TmpDir).

test_container_info() ->
    #{
        os_pid => 12345,
        socket_path => <<"/run/erlkoenig/containers/test.sock">>,
        ip => {10, 0, 1, 2},
        netns => <<"/proc/12345/ns/net">>,
        cgroup => <<"/sys/fs/cgroup/erlkoenig/test">>,
        veth_host => <<"veth_test_h">>,
        veth_container => <<"veth_test_c">>,
        bridge => <<"ek_br_default">>,
        zone => default,
        binary_path => <<"/opt/test/binary">>,
        config => #{name => <<"test">>},
        started_at => erlang:system_time(second),
        comm_mode => socket
    }.

%%====================================================================
%% Test generator
%%====================================================================

node_state_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun register_and_get/1,
      fun register_idempotent/1,
      fun unregister_container/1,
      fun unregister_missing/1,
      fun update_container/1,
      fun all_containers_empty/1,
      fun all_containers_multiple/1,
      fun get_not_found/1,
      fun register_with_full_info/1,
      fun update_partial/1,
      fun update_nonexistent/1,
      fun register_multiple_different_ids/1
     ]}.

persistence_test_() ->
    {"DETS persistence across restarts",
     fun() ->
         TmpDir = "/tmp/erlkoenig_dets_persist_" ++
                  integer_to_list(erlang:unique_integer([positive])),
         ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
         DetsPath = filename:join(TmpDir, "persist.dets"),

         %% Start, register, stop
         {ok, Pid1} = erlkoenig_node_state:start_link(DetsPath),
         ok = erlkoenig_node_state:register_container(<<"web-1">>, #{os_pid => 111}),
         gen_server:stop(Pid1),

         %% Start again with same path — data must survive
         {ok, Pid2} = erlkoenig_node_state:start_link(DetsPath),
         ?assertEqual({ok, #{os_pid => 111}},
                      erlkoenig_node_state:get_container(<<"web-1">>)),
         gen_server:stop(Pid2),
         os:cmd("rm -rf " ++ TmpDir)
     end}.

crash_safety_test_() ->
    {"DETS survives gen_server kill",
     fun() ->
         TmpDir = "/tmp/erlkoenig_dets_crash_" ++
                  integer_to_list(erlang:unique_integer([positive])),
         ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
         DetsPath = filename:join(TmpDir, "crash.dets"),

         %% Start, register, KILL (not stop)
         {ok, Pid1} = erlkoenig_node_state:start_link(DetsPath),
         ok = erlkoenig_node_state:register_container(<<"web-2">>,
                  #{os_pid => 222, comm_mode => socket}),
         unlink(Pid1),
         exit(Pid1, kill),
         %% Wait for process to actually die
         MRef = monitor(process, Pid1),
         receive {'DOWN', MRef, process, Pid1, _} -> ok
         after 1000 -> error(timeout)
         end,

         %% The DETS table name is registered — need to make sure it's
         %% cleaned up. dets:close may have been skipped due to kill.
         _ = dets:close(erlkoenig_node_state),

         %% Start again — data must survive
         {ok, Pid2} = erlkoenig_node_state:start_link(DetsPath),
         ?assertEqual({ok, #{os_pid => 222, comm_mode => socket}},
                      erlkoenig_node_state:get_container(<<"web-2">>)),
         gen_server:stop(Pid2),
         os:cmd("rm -rf " ++ TmpDir)
     end}.

%%====================================================================
%% Individual test functions
%%====================================================================

register_and_get({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info = #{os_pid => 100, comm_mode => socket},
        ok = erlkoenig_node_state:register_container(<<"c1">>, Info),
        {ok, Got} = erlkoenig_node_state:get_container(<<"c1">>),
        ?assertEqual(100, maps:get(os_pid, Got)),
        ?assertEqual(socket, maps:get(comm_mode, Got))
    end.

register_idempotent({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ok = erlkoenig_node_state:register_container(<<"c1">>, #{os_pid => 100}),
        ok = erlkoenig_node_state:register_container(<<"c1">>, #{os_pid => 200}),
        {ok, Got} = erlkoenig_node_state:get_container(<<"c1">>),
        ?assertEqual(200, maps:get(os_pid, Got))
    end.

unregister_container({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ok = erlkoenig_node_state:register_container(<<"c1">>, #{os_pid => 100}),
        ok = erlkoenig_node_state:unregister_container(<<"c1">>),
        ?assertEqual({error, not_found},
                     erlkoenig_node_state:get_container(<<"c1">>))
    end.

unregister_missing({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        %% Must not crash
        ok = erlkoenig_node_state:unregister_container(<<"nonexistent">>)
    end.

update_container({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ok = erlkoenig_node_state:register_container(<<"c1">>,
                 #{os_pid => 100, ip => {10, 0, 0, 2}}),
        ok = erlkoenig_node_state:update_container(<<"c1">>,
                 #{ip => {10, 0, 0, 99}}),
        {ok, Got} = erlkoenig_node_state:get_container(<<"c1">>),
        %% ip updated
        ?assertEqual({10, 0, 0, 99}, maps:get(ip, Got)),
        %% os_pid unchanged
        ?assertEqual(100, maps:get(os_pid, Got))
    end.

all_containers_empty({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ?assertEqual([], erlkoenig_node_state:all_containers())
    end.

all_containers_multiple({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ok = erlkoenig_node_state:register_container(<<"a">>, #{os_pid => 1}),
        ok = erlkoenig_node_state:register_container(<<"b">>, #{os_pid => 2}),
        ok = erlkoenig_node_state:register_container(<<"c">>, #{os_pid => 3}),
        All = erlkoenig_node_state:all_containers(),
        ?assertEqual(3, length(All)),
        Ids = lists:sort([Id || {Id, _} <- All]),
        ?assertEqual([<<"a">>, <<"b">>, <<"c">>], Ids)
    end.

get_not_found({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ?assertEqual({error, not_found},
                     erlkoenig_node_state:get_container(<<"ghost">>))
    end.

register_with_full_info({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info = test_container_info(),
        ok = erlkoenig_node_state:register_container(<<"full">>, Info),
        {ok, Got} = erlkoenig_node_state:get_container(<<"full">>),
        ?assertEqual(12345, maps:get(os_pid, Got)),
        ?assertEqual(<<"/run/erlkoenig/containers/test.sock">>,
                     maps:get(socket_path, Got)),
        ?assertEqual({10, 0, 1, 2}, maps:get(ip, Got)),
        ?assertEqual(default, maps:get(zone, Got)),
        ?assertEqual(socket, maps:get(comm_mode, Got)),
        ?assertEqual(<<"veth_test_h">>, maps:get(veth_host, Got)),
        ?assertEqual(<<"veth_test_c">>, maps:get(veth_container, Got)),
        ?assertEqual(<<"ek_br_default">>, maps:get(bridge, Got)),
        ?assertEqual(<<"/opt/test/binary">>, maps:get(binary_path, Got))
    end.

update_partial({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info = #{os_pid => 100, ip => {10, 0, 0, 2},
                 comm_mode => socket, zone => default},
        ok = erlkoenig_node_state:register_container(<<"c1">>, Info),
        %% Update only os_pid
        ok = erlkoenig_node_state:update_container(<<"c1">>, #{os_pid => 999}),
        {ok, Got} = erlkoenig_node_state:get_container(<<"c1">>),
        ?assertEqual(999, maps:get(os_pid, Got)),
        %% All other fields unchanged
        ?assertEqual({10, 0, 0, 2}, maps:get(ip, Got)),
        ?assertEqual(socket, maps:get(comm_mode, Got)),
        ?assertEqual(default, maps:get(zone, Got))
    end.

update_nonexistent({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        %% Update on non-existent container silently succeeds (returns ok)
        ?assertEqual(ok,
                     erlkoenig_node_state:update_container(<<"ghost">>,
                         #{os_pid => 42})),
        %% But container is still not there
        ?assertEqual({error, not_found},
                     erlkoenig_node_state:get_container(<<"ghost">>))
    end.

register_multiple_different_ids({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ok = erlkoenig_node_state:register_container(<<"web-1">>,
                 #{os_pid => 100, zone => dmz}),
        ok = erlkoenig_node_state:register_container(<<"db-1">>,
                 #{os_pid => 200, zone => internal}),
        {ok, Web} = erlkoenig_node_state:get_container(<<"web-1">>),
        {ok, Db} = erlkoenig_node_state:get_container(<<"db-1">>),
        ?assertEqual(100, maps:get(os_pid, Web)),
        ?assertEqual(200, maps:get(os_pid, Db)),
        ?assertEqual(dmz, maps:get(zone, Web)),
        ?assertEqual(internal, maps:get(zone, Db))
    end.
