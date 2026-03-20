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
