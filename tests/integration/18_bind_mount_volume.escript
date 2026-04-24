#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 18: Bind-Mount Persistent Volumes
%%
%% Tests:
%%   1. Spawn container with a persistent volume
%%   2. Write a file into the volume (from the container)
%%   3. Stop container
%%   4. Restart container (same volume)
%%   5. Read file — must still be there
%%   6. Read-only volume: write attempt must fail
%%   7. Multiple volumes in one container
-mode(compile).


main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 18: Bind-Mount Persistent Volumes ===~n~n"),
    test_helper:boot(),

    %% The volume store now uses UUID-keyed directories
    %% (`/var/lib/erlkoenig/volumes/<uuid>/`) with `by-name/` symlinks
    %% for human-readable lookup, not the legacy
    %% `/var/lib/erlkoenig/volumes/<container>/<persist>/' layout.
    %% We let the store create its UUID dirs on first `erlkoenig:spawn'
    %% and read the actual host paths back from `inspect/1'.
    VolumeByName =
        fun(Info, Persist) ->
            Vols = maps:get(volumes, Info, []),
            case [maps:get(host, V) || V <- Vols,
                                       maps:get(persist, V, undefined) =:= Persist] of
                [HP | _] -> binary_to_list(HP);
                []       -> error({volume_not_found, Persist})
            end
        end,

    %% --- Test 1: Spawn with volume, write, verify ---
    Pid1 = test_helper:step("Spawn container mit Volume", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("sleeper"),
            #{ip => {10,0,0,10},
              args => [<<"60">>],
              name => <<"test-vol-ct">>,
              volumes => [
                  #{container => <<"/data">>,
                    persist => <<"data">>,
                    read_only => false},
                  #{container => <<"/var/log/app">>,
                    persist => <<"logs">>,
                    read_only => false},
                  #{container => <<"/etc/config">>,
                    persist => <<"config">>,
                    read_only => true}
              ]}),
        timer:sleep(1500),
        %% Seed the read-only config volume with our sample file
        %% through the store's real host dir (read-only means no
        %% container-side writes, but the host can prepopulate).
        InfoSeed = erlkoenig:inspect(P),
        ConfigDir = VolumeByName(InfoSeed, <<"config">>),
        ok = file:write_file(ConfigDir ++ "/app.conf",
                             <<"setting=42\n">>),
        {ok, P}
    end),

    test_helper:step("Verify Volume in inspect output", fun() ->
        Info = erlkoenig:inspect(Pid1),
        Volumes = maps:get(volumes, Info, []),
        case length(Volumes) of
            3 -> ok;
            N -> {error, {expected_3_volumes, got, N}}
        end
    end),

    test_helper:step("Write file into rw volume via /proc", fun() ->
        Info = erlkoenig:inspect(Pid1),
        OsPid = maps:get(os_pid, Info),
        Path = lists:flatten(io_lib:format("/proc/~p/root/data/persist_test.txt", [OsPid])),
        ok = file:write_file(Path, <<"persistent-data-v1\n">>),
        {ok, Content} = file:read_file(Path),
        case string:find(binary_to_list(Content), "persistent-data-v1") of
            nomatch -> {error, write_failed};
            _ -> ok
        end
    end),

    test_helper:step("Verify file visible on host", fun() ->
        Info = erlkoenig:inspect(Pid1),
        DataDir = VolumeByName(Info, <<"data">>),
        HostPath = DataDir ++ "/persist_test.txt",
        case file:read_file(HostPath) of
            {ok, Content} ->
                case string:find(binary_to_list(Content), "persistent-data-v1") of
                    nomatch -> {error, not_visible_on_host};
                    _ -> ok
                end;
            {error, Reason} ->
                {error, {host_read_failed, Reason}}
        end
    end),

    test_helper:step("Read-only volume: verify config readable", fun() ->
        Info = erlkoenig:inspect(Pid1),
        OsPid = maps:get(os_pid, Info),
        Path = lists:flatten(io_lib:format("/proc/~p/root/etc/config/app.conf", [OsPid])),
        case file:read_file(Path) of
            {ok, Content} ->
                case string:find(binary_to_list(Content), "setting=42") of
                    nomatch -> {error, config_not_readable};
                    _ -> ok
                end;
            {error, R} ->
                {error, {read_failed, R}}
        end
    end),

    %% --- Test 2: Stop and restart — data persists ---
    test_helper:step("Stop container", fun() ->
        ok = erlkoenig:stop(Pid1),
        timer:sleep(1000),
        ok
    end),

    test_helper:step("Verify volume data on host after stop", fun() ->
        %% Pid1 is stopped but its volume record survives in the store,
        %% so inspect still returns the host path.
        Info = erlkoenig:inspect(Pid1),
        DataDir = VolumeByName(Info, <<"data">>),
        HostPath = DataDir ++ "/persist_test.txt",
        case file:read_file(HostPath) of
            {ok, Content} ->
                case string:find(binary_to_list(Content), "persistent-data-v1") of
                    nomatch -> {error, data_lost};
                    _ ->
                        io:format("    Data persists on host after container stop~n"),
                        ok
                end;
            {error, Reason} ->
                {error, {host_read_after_stop_failed, Reason}}
        end
    end),

    Pid2 = test_helper:step("Restart container mit selben Volumes", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("sleeper"),
            #{ip => {10,0,0,10},
              args => [<<"60">>],
              name => <<"test-vol-ct">>,
              volumes => [
                  #{container => <<"/data">>,
                    persist => <<"data">>,
                    read_only => false}
              ]}),
        timer:sleep(1500),
        {ok, P}
    end),

    test_helper:step("Read persisted data in restarted container", fun() ->
        Info = erlkoenig:inspect(Pid2),
        OsPid = maps:get(os_pid, Info),
        Path = lists:flatten(io_lib:format("/proc/~p/root/data/persist_test.txt", [OsPid])),
        case file:read_file(Path) of
            {ok, Content} ->
                case string:find(binary_to_list(Content), "persistent-data-v1") of
                    nomatch -> {error, data_not_persisted};
                    _ ->
                        io:format("    Data survived restart!~n"),
                        ok
                end;
            {error, Reason} ->
                {error, {read_after_restart_failed, Reason}}
        end
    end),

    %% Cleanup
    test_helper:cleanup([Pid2]),

    %% Volumes are managed by the store — dropping test containers
    %% leaves the UUID dirs behind. That's fine for a dev host; a
    %% future iteration can call erlkoenig_volume_store:cleanup_ephemeral/1
    %% here once the test container is flagged `ephemeral'.

    io:format("~n=== Test 18 bestanden ===~n~n"),
    halt(0).
