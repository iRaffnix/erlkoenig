%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_cgroup (path construction, limits).
%%%
%%% Tests internal logic without requiring cgroupfs.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_cgroup_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% =================================================================
%% Path construction
%% =================================================================

container_path_test() ->
    %% container_path/1 joins /sys/fs/cgroup/erlkoenig/ + ID
    Path = filename:join("/sys/fs/cgroup/erlkoenig",
                         binary_to_list(<<"abc123">>)),
    ?assertEqual("/sys/fs/cgroup/erlkoenig/abc123", Path).

container_path_uuid_test() ->
    Id = <<"550e8400-e29b-41d4-a716-446655440000">>,
    Path = filename:join("/sys/fs/cgroup/erlkoenig", binary_to_list(Id)),
    ?assert(lists:prefix("/sys/fs/cgroup/erlkoenig/550e8400", Path)).

%% =================================================================
%% CPU limit formatting
%% =================================================================

cpu_limit_50_percent_test() ->
    %% 50% of one core = 500000 out of 1000000 period
    Period = 1_000_000,
    Percent = 50,
    Quota = round(Percent / 100 * Period),
    Value = integer_to_list(Quota) ++ " " ++ integer_to_list(Period),
    ?assertEqual("500000 1000000", Value).

cpu_limit_100_percent_test() ->
    Period = 1_000_000,
    Quota = round(100 / 100 * Period),
    Value = integer_to_list(Quota) ++ " " ++ integer_to_list(Period),
    ?assertEqual("1000000 1000000", Value).

cpu_limit_1_percent_test() ->
    Period = 1_000_000,
    Quota = round(1 / 100 * Period),
    Value = integer_to_list(Quota) ++ " " ++ integer_to_list(Period),
    ?assertEqual("10000 1000000", Value).

%% =================================================================
%% cpu.stat parsing
%% =================================================================

parse_cpu_stat_test() ->
    %% Simulating the cpu.stat file format
    Bin = <<"usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n">>,
    Lines = binary:split(Bin, <<"\n">>, [global]),
    Result = find_usage_usec(Lines),
    ?assertEqual({ok, 123456}, Result).

parse_cpu_stat_missing_test() ->
    Bin = <<"user_usec 100000\nsystem_usec 23456\n">>,
    Lines = binary:split(Bin, <<"\n">>, [global]),
    Result = find_usage_usec(Lines),
    ?assertEqual(error, Result).

%% Helper that mirrors erlkoenig_cgroup:parse_cpu_usage_lines/1
find_usage_usec([]) -> error;
find_usage_usec([Line | Rest]) ->
    case binary:split(Line, <<" ">>) of
        [<<"usage_usec">>, Val] ->
            try {ok, binary_to_integer(string:trim(Val))}
            catch _:_ -> error
            end;
        _ ->
            find_usage_usec(Rest)
    end.

%% =================================================================
%% Memory limit formatting
%% =================================================================

memory_limit_format_test() ->
    %% memory.max takes bytes as a plain integer string
    Bytes = 64_000_000,
    ?assertEqual("64000000", integer_to_list(Bytes)).

pids_limit_format_test() ->
    Max = 128,
    ?assertEqual("128", integer_to_list(Max)).

%% =================================================================
%% cgroup v2 path parsing
%% =================================================================

parse_cgroup_v2_root_test() ->
    %% Root cgroup: "0::/"
    Bin = <<"0::/\n">>,
    ?assertEqual({ok, "/"}, parse_v2_path(Bin)).

parse_cgroup_v2_systemd_test() ->
    %% Systemd delegated cgroup
    Bin = <<"0::/system.slice/erlkoenig.service\n">>,
    ?assertEqual({ok, "/system.slice/erlkoenig.service"}, parse_v2_path(Bin)).

parse_cgroup_v2_user_test() ->
    %% User session cgroup
    Bin = <<"0::/user.slice/user-1000.slice/session-1.scope\n">>,
    ?assertEqual({ok, "/user.slice/user-1000.slice/session-1.scope"}, parse_v2_path(Bin)).

parse_cgroup_v2_missing_test() ->
    %% No cgroup v2 line
    Bin = <<"1:name=systemd:/init.scope\n">>,
    ?assertEqual(error, parse_v2_path(Bin)).

%% Helper that mirrors erlkoenig_cgroup:parse_cgroup_v2_path/1
parse_v2_path(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    parse_v2_lines(Lines).

parse_v2_lines([]) -> error;
parse_v2_lines([<<"0::", Path/binary>> | _]) ->
    {ok, binary_to_list(string:trim(Path))};
parse_v2_lines([_ | Rest]) ->
    parse_v2_lines(Rest).

%% =================================================================
%% Topology paths (A1)
%% =================================================================

topology_paths_test() ->
    Base = "/sys/fs/cgroup/system.slice/erlkoenig.service/erlkoenig",
    BeamPath = filename:join(Base, "beam"),
    ContainersPath = filename:join(Base, "containers"),
    ?assertEqual(Base ++ "/beam", BeamPath),
    ?assertEqual(Base ++ "/containers", ContainersPath).

container_path_under_containers_test() ->
    ContainersPath = "/sys/fs/cgroup/erlkoenig/containers",
    Id = <<"web-1">>,
    Path = filename:join(ContainersPath, binary_to_list(Id)),
    ?assertEqual("/sys/fs/cgroup/erlkoenig/containers/web-1", Path).

container_path_not_under_base_test() ->
    %% Container path must contain /containers/ segment — not directly under base
    ContainersPath = "/sys/fs/cgroup/erlkoenig/containers",
    Id = <<"test-abc">>,
    Path = filename:join(ContainersPath, binary_to_list(Id)),
    ?assertNotEqual(nomatch, string:find(Path, "/containers/")),
    %% Verify it's NOT base_path + id (old layout)
    BasePath = "/sys/fs/cgroup/erlkoenig",
    OldStylePath = filename:join(BasePath, binary_to_list(Id)),
    ?assertNotEqual(OldStylePath, Path).

%% =================================================================
%% Configuration — pure functions (A2)
%% =================================================================

beam_config_defaults_test() ->
    %% Ensure no resource_protection is set so we get defaults
    application:unset_env(erlkoenig, resource_protection),
    Cfg = erlkoenig_cgroup:beam_config(),
    ?assertEqual(268_435_456, maps:get(memory_min, Cfg)),
    ?assertEqual(536_870_912, maps:get(memory_max, Cfg)),
    ?assertEqual(200, maps:get(cpu_weight, Cfg)),
    ?assertEqual(8192, maps:get(pids_max, Cfg)).

beam_config_override_test() ->
    application:set_env(erlkoenig, resource_protection, #{
        beam_memory_min => 512_000_000,
        beam_memory_max => 1_024_000_000,
        beam_cpu_weight => 300,
        beam_pids_max   => 16384
    }),
    Cfg = erlkoenig_cgroup:beam_config(),
    ?assertEqual(512_000_000, maps:get(memory_min, Cfg)),
    ?assertEqual(1_024_000_000, maps:get(memory_max, Cfg)),
    ?assertEqual(300, maps:get(cpu_weight, Cfg)),
    ?assertEqual(16384, maps:get(pids_max, Cfg)),
    application:unset_env(erlkoenig, resource_protection).

containers_config_explicit_test() ->
    application:set_env(erlkoenig, resource_protection, #{
        containers_memory_max => 4_000_000_000,
        containers_pids_max   => 24576
    }),
    Cfg = erlkoenig_cgroup:containers_config(),
    ?assertEqual(4_000_000_000, maps:get(memory_max, Cfg)),
    ?assertEqual(24576, maps:get(pids_max, Cfg)),
    application:unset_env(erlkoenig, resource_protection).

compute_ceiling_8gb_test() ->
    Result = erlkoenig_cgroup:compute_containers_memory_max(
        8_589_934_592, 1_073_741_824, 536_870_912),
    ?assertEqual(6_979_321_856, Result).

compute_ceiling_4gb_test() ->
    Result = erlkoenig_cgroup:compute_containers_memory_max(
        4_294_967_296, 1_073_741_824, 536_870_912),
    ?assertEqual(2_684_354_560, Result).

parse_memtotal_test() ->
    Bin = <<"MemTotal:        8028256 kB\nMemFree:         1234567 kB\n">>,
    ?assertEqual({ok, 8028256 * 1024}, erlkoenig_cgroup:parse_memtotal(Bin)).

parse_memtotal_missing_test() ->
    Bin = <<"MemFree:         1234567 kB\nBuffers:          123456 kB\n">>,
    ?assertEqual(error, erlkoenig_cgroup:parse_memtotal(Bin)).

%% =================================================================
%% Validation (A2)
%% =================================================================

validate_beam_min_zero_test() ->
    BadCfg = #{memory_min => 0, memory_max => 536_870_912,
               cpu_weight => 200, pids_max => 8192},
    ?assertError({invalid_config, beam_memory_min_must_be_positive, 0},
                 erlkoenig_cgroup:validate_beam_config(BadCfg)).

validate_beam_max_lt_min_test() ->
    BadCfg = #{memory_min => 536_870_912, memory_max => 268_435_456,
               cpu_weight => 200, pids_max => 8192},
    ?assertError({invalid_config, beam_memory_max_lt_min, _},
                 erlkoenig_cgroup:validate_beam_config(BadCfg)).

validate_beam_valid_test() ->
    GoodCfg = #{memory_min => 268_435_456, memory_max => 536_870_912,
                 cpu_weight => 200, pids_max => 8192},
    ?assertEqual(ok, erlkoenig_cgroup:validate_beam_config(GoodCfg)).

validate_containers_too_low_test() ->
    %% 128 MB = 134_217_728, use one byte less
    BadCfg = #{memory_max => 134_217_727, pids_max => 24576},
    ?assertError({invalid_config, containers_memory_max_too_low, _},
                 erlkoenig_cgroup:validate_containers_config(BadCfg)).

validate_containers_valid_test() ->
    GoodCfg = #{memory_max => 4_000_000_000, pids_max => 24576},
    ?assertEqual(ok, erlkoenig_cgroup:validate_containers_config(GoodCfg)).

auto_ceiling_negative_test() ->
    %% host_reserve + beam_max >= MemTotal → result below 128 MB minimum
    %% 2 GB total, 1 GB host reserve, 1.5 GB beam max → -0.5 GB
    Ceiling = erlkoenig_cgroup:compute_containers_memory_max(
        2_147_483_648, 1_073_741_824, 1_610_612_736),
    %% Ceiling is negative, which is below MIN_CONTAINERS_MEMORY
    BadCfg = #{memory_max => Ceiling, pids_max => 24576},
    ?assertError({invalid_config, containers_memory_max_too_low, _},
                 erlkoenig_cgroup:validate_containers_config(BadCfg)).
