%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_cgroup_stats_tests).

-include_lib("eunit/include/eunit.hrl").

payload_includes_headroom_for_bounded_containers_subtree_test() ->
    Payload = erlkoenig_cgroup_stats:payload(#{
        memory_bytes => 600,
        memory_peak => 700,
        memory_max => 1000,
        cpu_usec => 12345,
        pids_current => 4,
        pids_max => 10
    }),
    ?assertEqual(containers, maps:get(scope, Payload)),
    ?assertEqual(600, maps:get(memory_current, Payload)),
    ?assertEqual(700, maps:get(memory_peak, Payload)),
    ?assertEqual(1000, maps:get(memory_max, Payload)),
    ?assertEqual(400, maps:get(memory_available, Payload)),
    ?assertEqual(60.0, maps:get(memory_pct, Payload)),
    ?assertEqual(12345, maps:get(cpu_usec, Payload)),
    ?assertEqual(4, maps:get(pids_current, Payload)),
    ?assertEqual(10, maps:get(pids_max, Payload)),
    ?assertEqual(6, maps:get(pids_available, Payload)),
    ?assertEqual(40.0, maps:get(pids_pct, Payload)),
    ?assert(is_integer(maps:get(ts_ms, Payload))).

payload_omits_headroom_for_unbounded_limits_test() ->
    Payload = erlkoenig_cgroup_stats:payload(#{
        memory_bytes => 600,
        memory_max => max,
        pids_current => 4,
        pids_max => max
    }),
    ?assertEqual(max, maps:get(memory_max, Payload)),
    ?assertEqual(max, maps:get(pids_max, Payload)),
    ?assertNot(maps:is_key(memory_available, Payload)),
    ?assertNot(maps:is_key(memory_pct, Payload)),
    ?assertNot(maps:is_key(pids_available, Payload)),
    ?assertNot(maps:is_key(pids_pct, Payload)).
