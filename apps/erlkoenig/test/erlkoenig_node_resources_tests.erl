%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_node_resources_tests).

-include_lib("eunit/include/eunit.hrl").

node_resources_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun t_initial_snapshot_populated/1,
      fun t_rejects_without_memory_limit/1,
      fun t_rejects_without_pids_limit/1,
      fun t_rejects_insufficient_memory/1,
      fun t_rejects_insufficient_pids/1,
      fun t_committed_prevents_double_booking/1,
      fun t_confirm_running_releases_commit/1,
      fun t_release_commit_idempotent/1,
      fun t_degraded_allocated_snapshot_rejects_admission/1,
      fun t_container_limit_reached/1]}.

setup() ->
    _ = ensure_pg(),
    Previous = application:get_env(erlkoenig, resource_protection),
    application:set_env(erlkoenig, resource_protection, #{
        mode => development,
        containers_memory_max => 268_435_456,
        containers_pids_max => 100,
        containers_max => 2,
        require_memory_limit => true,
        require_pids_limit => true
    }),
    {ok, _} = erlkoenig_node_resources:start_link(),
    #{previous => Previous}.

cleanup(#{previous := Previous}) ->
    case whereis(erlkoenig_node_resources) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid, normal, 5_000)
    end,
    catch ets:delete(erlkoenig_node_resources),
    case Previous of
        undefined -> application:unset_env(erlkoenig, resource_protection);
        {ok, Old} -> application:set_env(erlkoenig, resource_protection, Old)
    end,
    ok.

t_initial_snapshot_populated(_) ->
    ?_test(begin
        Cap = erlkoenig_node_resources:get_capacity(),
        ?assertEqual(268_435_456, maps:get(containers_ceiling, Cap)),
        ?assertEqual(100, maps:get(containers_pids_max, Cap)),
        ?assertEqual(2, maps:get(containers_max, Cap)),
        ?assertEqual(true, maps:get(require_memory_limit, Cap)),
        ?assertEqual(true, maps:get(require_pids_limit, Cap)),
        ?assert(maps:is_key(allocatable_memory, Cap)),
        ?assert(maps:is_key(allocatable_pids, Cap)),
        ?assertEqual([], maps:get(memory_allocated_sources, Cap)),
        ?assertEqual([], maps:get(memory_committed_sources, Cap)),
        ?assertEqual([], maps:get(pids_allocated_sources, Cap)),
        ?assertEqual([], maps:get(pids_committed_sources, Cap))
    end).

t_rejects_without_memory_limit(_) ->
    ?_test(begin
        {error, Denial} =
            erlkoenig_node_resources:admit(<<"no-mem">>, #{pids => 10}),
        ?assertEqual(no_memory_limit_declared, maps:get(reason, Denial)),
        ?assertEqual(true, maps:get(required, Denial))
    end).

t_rejects_without_pids_limit(_) ->
    ?_test(begin
        {error, Denial} =
            erlkoenig_node_resources:admit(<<"no-pids">>,
                                           #{memory => 64_000_000}),
        ?assertEqual(no_pids_limit_declared, maps:get(reason, Denial)),
        ?assertEqual(true, maps:get(required, Denial))
    end).

t_rejects_insufficient_memory(_) ->
    ?_test(begin
        {error, Denial} =
            erlkoenig_node_resources:admit(<<"too-big">>,
                                           #{memory => 300_000_000,
                                             pids => 10}),
        ?assertEqual(insufficient_memory, maps:get(reason, Denial)),
        ?assertEqual(300_000_000, maps:get(required, Denial)),
        ?assertEqual(268_435_456, maps:get(available, Denial)),
        Evidence = maps:get(evidence, Denial),
        ?assertEqual(memory, maps:get(kind, Evidence)),
        ?assertEqual(268_435_456, maps:get(ceiling, Evidence)),
        ?assertEqual(0, maps:get(allocated, Evidence)),
        ?assertEqual(0, maps:get(committed, Evidence)),
        ?assertEqual([], maps:get(allocated_sources, Evidence)),
        ?assertEqual([], maps:get(committed_sources, Evidence)),
        ?assert(maps:is_key(last_updated, Evidence))
    end).

t_rejects_insufficient_pids(_) ->
    ?_test(begin
        {error, Denial} =
            erlkoenig_node_resources:admit(<<"too-many-pids">>,
                                           #{memory => 64_000_000,
                                             pids => 101}),
        ?assertEqual(insufficient_pids, maps:get(reason, Denial)),
        ?assertEqual(101, maps:get(required, Denial)),
        ?assertEqual(100, maps:get(available, Denial)),
        Evidence = maps:get(evidence, Denial),
        ?assertEqual(pids, maps:get(kind, Evidence)),
        ?assertEqual(100, maps:get(ceiling, Evidence)),
        ?assertEqual(0, maps:get(allocated, Evidence)),
        ?assertEqual(0, maps:get(committed, Evidence)),
        ?assertEqual([], maps:get(allocated_sources, Evidence)),
        ?assertEqual([], maps:get(committed_sources, Evidence)),
        ?assert(maps:is_key(last_updated, Evidence))
    end).

t_committed_prevents_double_booking(_) ->
    ?_test(begin
        ok = erlkoenig_node_resources:admit(<<"a">>,
                                            #{memory => 200_000_000,
                                              pids => 60}),
        Cap = erlkoenig_node_resources:get_capacity(),
        ?assertEqual(200_000_000, maps:get(memory_committed, Cap)),
        ?assertEqual(60, maps:get(pids_committed, Cap)),
        [MemSource] = maps:get(memory_committed_sources, Cap),
        [PidsSource] = maps:get(pids_committed_sources, Cap),
        ?assertEqual(<<"a">>, maps:get(id, MemSource)),
        ?assertEqual(memory, maps:get(kind, MemSource)),
        ?assertEqual(200_000_000, maps:get(value, MemSource)),
        ?assert(maps:is_key(since_ms, MemSource)),
        ?assertEqual(<<"a">>, maps:get(id, PidsSource)),
        ?assertEqual(pids, maps:get(kind, PidsSource)),
        ?assertEqual(60, maps:get(value, PidsSource)),
        ?assert(maps:is_key(since_ms, PidsSource)),
        {error, Denial} =
            erlkoenig_node_resources:admit(<<"b">>,
                                           #{memory => 100_000_000,
                                             pids => 10}),
        ?assertEqual(insufficient_memory, maps:get(reason, Denial)),
        ?assertEqual(100_000_000, maps:get(required, Denial)),
        ?assertEqual(68_435_456, maps:get(available, Denial)),
        Evidence = maps:get(evidence, Denial),
        [EvidenceSource] = maps:get(committed_sources, Evidence),
        ?assertEqual(<<"a">>, maps:get(id, EvidenceSource)),
        ?assertEqual(200_000_000, maps:get(value, EvidenceSource)),
        ?assert(maps:is_key(since_ms, EvidenceSource))
    end).

t_confirm_running_releases_commit(_) ->
    ?_test(begin
        ok = erlkoenig_node_resources:admit(<<"run">>,
                                            #{memory => 64_000_000,
                                              pids => 10}),
        ok = erlkoenig_node_resources:confirm_running(<<"run">>),
        Cap = erlkoenig_node_resources:get_capacity(),
        ?assertEqual(0, maps:get(memory_committed, Cap)),
        ?assertEqual(0, maps:get(pids_committed, Cap))
    end).

t_release_commit_idempotent(_) ->
    ?_test(begin
        ok = erlkoenig_node_resources:admit(<<"x">>,
                                            #{memory => 64_000_000,
                                              pids => 10}),
        ok = erlkoenig_node_resources:release_commit(<<"x">>),
        ok = erlkoenig_node_resources:release_commit(<<"x">>),
        Cap = erlkoenig_node_resources:get_capacity(),
        ?assertEqual(0, maps:get(memory_committed, Cap)),
        ?assertEqual(0, maps:get(pids_committed, Cap))
    end).

t_degraded_allocated_snapshot_rejects_admission(_) ->
    ?_test(begin
        BadPid = spawn(fun() ->
            receive stop -> ok after 5_000 -> ok end
        end),
        ok = pg:join(erlkoenig_pg, erlkoenig_cts, BadPid),
        try
            {error, Evidence} =
                erlkoenig_node_resources:admit(<<"degraded">>,
                                               #{memory => 1,
                                                 pids => 1}),
            ?assertEqual(node_resources_unavailable,
                         maps:get(reason, Evidence)),
            ?assertEqual(allocated_snapshot_degraded,
                         maps:get(cause, Evidence)),
            [_ | _] = maps:get(read_errors, Evidence),
            ?assert(maps:is_key(last_updated, Evidence))
        after
            _ = pg:leave(erlkoenig_pg, erlkoenig_cts, BadPid),
            BadPid ! stop
        end
    end).

t_container_limit_reached(_) ->
    ?_test(begin
        %% Manual commits don't increment running count; use tiny
        %% containers_max=0 in a restarted fixture to pin the count check.
        gen_server:stop(erlkoenig_node_resources, normal, 5_000),
        application:set_env(erlkoenig, resource_protection, #{
            mode => development,
            containers_memory_max => 268_435_456,
            containers_pids_max => 100,
            containers_max => 0,
            require_memory_limit => true,
            require_pids_limit => true
        }),
        {ok, _} = erlkoenig_node_resources:start_link(),
        {error, Denial} =
            erlkoenig_node_resources:admit(<<"limit">>,
                                           #{memory => 1,
                                             pids => 1}),
        ?assertEqual(container_limit_reached, maps:get(reason, Denial)),
        ?assertEqual(0, maps:get(max, Denial))
    end).

parse_meminfo_test() ->
    Bin = <<"MemTotal:        8028256 kB\n",
            "MemAvailable:    1234567 kB\n">>,
    ?assertEqual({ok, #{memory_total => 8028256 * 1024,
                        memory_available => 1234567 * 1024}},
                 erlkoenig_node_resources:parse_meminfo(Bin)).

ensure_pg() ->
    case whereis(erlkoenig_pg) of
        undefined ->
            case pg:start_link(erlkoenig_pg) of
                {ok, _Pid} -> ok;
                {error, {already_started, _Pid}} -> ok
            end;
        _Pid ->
            ok
    end.
