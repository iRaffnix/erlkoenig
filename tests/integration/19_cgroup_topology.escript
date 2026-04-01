#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 19: cgroup Topology — beam/ + containers/ layout after boot
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 19: cgroup Topology ===~n~n"),
    test_helper:boot(),

    %% Derive the cgroup base path from /proc/self/cgroup
    BasePath = test_helper:step("beam/ und containers/ existieren", fun() ->
        Base = detect_base_path(),
        BeamDir = filename:join(Base, "beam"),
        ContainersDir = filename:join(Base, "containers"),
        io:format("    base=~s~n", [Base]),
        true = filelib:is_dir(BeamDir),
        true = filelib:is_dir(ContainersDir),
        {ok, Base}
    end),

    BeamPath = filename:join(BasePath, "beam"),
    ContainersPath = filename:join(BasePath, "containers"),

    test_helper:step("BEAM PID in beam/cgroup.procs", fun() ->
        {ok, Bin} = file:read_file(filename:join(BeamPath, "cgroup.procs")),
        MyPid = list_to_binary(os:getpid()),
        Pids = binary:split(Bin, <<"\n">>, [global]),
        io:format("    BEAM os pid=~s~n", [MyPid]),
        case lists:member(MyPid, Pids) of
            true  -> ok;
            false -> {error, {beam_pid_not_found, MyPid, Pids}}
        end
    end),

    test_helper:step("beam/memory.min gesetzt", fun() ->
        Val = read_cgroup_int(BeamPath, "memory.min"),
        io:format("    memory.min=~b~n", [Val]),
        case Val > 0 of
            true  -> ok;
            false -> {error, {expected_nonzero, Val}}
        end
    end),

    test_helper:step("beam/memory.max gesetzt", fun() ->
        Val = read_cgroup_int(BeamPath, "memory.max"),
        io:format("    memory.max=~b~n", [Val]),
        case Val > 0 of
            true  -> ok;
            false -> {error, {expected_nonzero, Val}}
        end
    end),

    test_helper:step("beam/cpu.weight gesetzt", fun() ->
        Val = read_cgroup_int(BeamPath, "cpu.weight"),
        io:format("    cpu.weight=~b~n", [Val]),
        case Val > 0 of
            true  -> ok;
            false -> {error, {expected_nonzero, Val}}
        end
    end),

    test_helper:step("containers/memory.max gesetzt", fun() ->
        Val = read_cgroup_int(ContainersPath, "memory.max"),
        io:format("    memory.max=~b~n", [Val]),
        case Val > 0 of
            true  -> ok;
            false -> {error, {expected_nonzero, Val}}
        end
    end),

    Pid = test_helper:step("Container unter containers/", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("sleeper"),
            #{ip => {10,0,0,19}, args => [<<"30">>],
              limits => #{memory => 64_000_000, pids => 64}}),
        timer:sleep(500),
        Info = erlkoenig:inspect(P),
        Id = maps:get(id, Info),
        {ok, CgroupPath} = erlkoenig_cgroup:path(Id),
        io:format("    id=~s cgroup=~s~n", [Id, CgroupPath]),
        true = filelib:is_dir(CgroupPath),
        %% Verify the cgroup is under containers/
        true = lists:prefix(ContainersPath, CgroupPath),
        {ok, P}
    end),

    test_helper:step("path(Id) zeigt auf containers/", fun() ->
        Info = erlkoenig:inspect(Pid),
        Id = maps:get(id, Info),
        {ok, CgroupPath} = erlkoenig_cgroup:path(Id),
        io:format("    path=~s~n", [CgroupPath]),
        case string:find(CgroupPath, "/containers/") of
            nomatch -> {error, {path_missing_containers_segment, CgroupPath}};
            _       -> ok
        end
    end),

    test_helper:step("read_containers_stats", fun() ->
        {ok, Stats} = erlkoenig_cgroup:read_containers_stats(),
        io:format("    stats=~p~n", [Stats]),
        true = is_map_key(memory_bytes, Stats),
        true = is_map_key(pids_current, Stats),
        ok
    end),

    %% Cleanup
    catch erlkoenig:stop(Pid),
    timer:sleep(300),

    io:format("~n=== Test 19 bestanden ===~n~n"),
    halt(0).

%% Read the cgroup base path from /proc/self/cgroup.
%% Format: "0::/path\n" for cgroup v2.
detect_base_path() ->
    {ok, Bin} = file:read_file("/proc/self/cgroup"),
    Lines = binary:split(Bin, <<"\n">>, [global]),
    CgroupRel = parse_cgroup_v2(Lines),
    %% Strip trailing /beam since the BEAM has been moved there
    Base = case lists:suffix("/beam", CgroupRel) of
        true  -> lists:sublist(CgroupRel, length(CgroupRel) - 5);
        false -> CgroupRel
    end,
    "/sys/fs/cgroup" ++ Base.

parse_cgroup_v2([]) ->
    error(no_cgroup_v2_entry);
parse_cgroup_v2([<<"0::", Path/binary>> | _]) ->
    binary_to_list(string:trim(Path));
parse_cgroup_v2([_ | Rest]) ->
    parse_cgroup_v2(Rest).

%% Read an integer value from a cgroup control file.
read_cgroup_int(Dir, Filename) ->
    File = filename:join(Dir, Filename),
    {ok, Bin} = file:read_file(File),
    binary_to_integer(string:trim(Bin)).
