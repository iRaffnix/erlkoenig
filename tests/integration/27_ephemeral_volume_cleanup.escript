#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 27: Ephemeral Volume Cleanup + UUID-based Identity
%%
%% Exercises the new volume-identity model:
%%
%%   - UUID-based on-disk paths (/var/lib/erlkoenig/volumes/<uuid>/)
%%   - DETS-backed metadata store (erlkoenig_volume_store)
%%   - ephemeral: true in DSL → destroyed on container stop
%%   - ephemeral: false (default) → survives container destroy
%%   - by-name symlinks for operator visibility
%%
%% Layout:
%%   Container `test-ephemeral` has two volumes:
%%     /persist  — persistent, survives destroy
%%     /scratch  — ephemeral, gone after destroy
%%
%%   We write a marker file into each, stop the container, and verify:
%%     /persist host-dir still exists with marker
%%     /scratch host-dir is gone (metadata + data)
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 27: Ephemeral Volume Cleanup ===~n~n"),
    test_helper:boot(),

    VolRoot = <<"/var/lib/erlkoenig/volumes">>,
    CtName  = <<"test-ephemeral-ct">>,

    %% Clean slate: remove any prior ephemeral records for this name.
    %% We don't nuke the whole volumes root — persistent volumes from
    %% previous test runs should survive (that's the point).
    _ = erlkoenig_volume_store:cleanup_ephemeral(CtName),

    %% --- Step 1: spawn with one persistent + one ephemeral volume ---
    Pid = test_helper:step("Spawn container with mixed volumes", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("sleeper"),
            #{ip => {10,0,0,11},
              args => [<<"60">>],
              name => CtName,
              volumes => [
                  #{container => <<"/persist">>,
                    persist   => <<"persistvol">>,
                    ephemeral => false},
                  #{container => <<"/scratch">>,
                    persist   => <<"scratch">>,
                    ephemeral => true}
              ]}),
        timer:sleep(1500),
        {ok, P}
    end),

    %% --- Step 2: pull volume metadata from the store ---
    {PersistUuid, ScratchUuid, PersistHost, ScratchHost} =
        test_helper:step("Both volumes registered in store", fun() ->
            Records = erlkoenig_volume_store:list_by_container(CtName),
            case length(Records) of
                2 ->
                    P = find_by_persist(Records, <<"persistvol">>),
                    S = find_by_persist(Records, <<"scratch">>),
                    {ok, {maps:get(uuid, P), maps:get(uuid, S),
                          maps:get(host_path, P), maps:get(host_path, S)}};
                N ->
                    {error, {expected_2_volumes, got, N, Records}}
            end
        end),

    test_helper:step("UUID dirs exist on disk", fun() ->
        case {filelib:is_dir(binary_to_list(PersistHost)),
              filelib:is_dir(binary_to_list(ScratchHost))} of
            {true, true} ->
                io:format("    persist: ~s~n    scratch: ~s~n",
                          [PersistHost, ScratchHost]),
                ok;
            Other ->
                {error, {dirs_missing, Other}}
        end
    end),

    test_helper:step("by-name symlinks present", fun() ->
        PersistLink = filename:join([binary_to_list(VolRoot), "by-name",
                                     binary_to_list(CtName), "persistvol"]),
        ScratchLink = filename:join([binary_to_list(VolRoot), "by-name",
                                     binary_to_list(CtName), "scratch"]),
        case {file:read_link(PersistLink), file:read_link(ScratchLink)} of
            {{ok, _}, {ok, _}} -> ok;
            Other -> {error, {symlink_missing, Other}}
        end
    end),

    %% --- Step 3: drop marker files via /proc/<pid>/root ---
    test_helper:step("Write markers into both volumes", fun() ->
        Info = erlkoenig:inspect(Pid),
        OsPid = maps:get(os_pid, Info),
        PersistMarker = io_lib:format("/proc/~p/root/persist/marker.txt",
                                      [OsPid]),
        ScratchMarker = io_lib:format("/proc/~p/root/scratch/marker.txt",
                                      [OsPid]),
        ok = file:write_file(lists:flatten(PersistMarker),
                             <<"persistent-data\n">>),
        ok = file:write_file(lists:flatten(ScratchMarker),
                             <<"ephemeral-data\n">>),
        ok
    end),

    %% --- Step 4: stop the container (enters `stopped`) ---
    test_helper:step("Stop container", fun() ->
        ok = erlkoenig:stop(Pid),
        timer:sleep(1500),
        ok
    end),

    %% --- Step 5: verify cleanup behaviour ---
    test_helper:step("Ephemeral scratch dir removed from disk", fun() ->
        case filelib:is_dir(binary_to_list(ScratchHost)) of
            false -> ok;
            true  -> {error, {ephemeral_not_destroyed, ScratchHost}}
        end
    end),

    test_helper:step("Ephemeral scratch removed from store", fun() ->
        case erlkoenig_volume_store:find(CtName, <<"scratch">>) of
            not_found -> ok;
            {ok, _}   -> {error, metadata_not_cleaned}
        end
    end),

    test_helper:step("Persistent volume survives — dir + marker", fun() ->
        MarkerPath = filename:join(binary_to_list(PersistHost),
                                    "marker.txt"),
        case file:read_file(MarkerPath) of
            {ok, <<"persistent-data\n">>} ->
                io:format("    persist/marker.txt survived~n"),
                ok;
            {ok, Other}      -> {error, {wrong_content, Other}};
            {error, Reason}  -> {error, {marker_lost, Reason}}
        end
    end),

    test_helper:step("Persistent metadata survives in store", fun() ->
        case erlkoenig_volume_store:find(CtName, <<"persistvol">>) of
            {ok, #{uuid := U}} when U =:= PersistUuid -> ok;
            {ok, Other} -> {error, {wrong_record, Other}};
            not_found   -> {error, metadata_lost}
        end
    end),

    %% --- Cleanup: tear down the persistent volume we just verified ---
    test_helper:step("Manually destroy persistent volume", fun() ->
        ok = erlkoenig_volume_store:destroy(PersistUuid),
        case {erlkoenig_volume_store:find(CtName, <<"persistvol">>),
              filelib:is_dir(binary_to_list(PersistHost))} of
            {not_found, false} -> ok;
            Other              -> {error, {destroy_incomplete, Other}}
        end
    end),

    %% ScratchUuid captured for completeness; the ephemeral-cleanup
    %% step above already removed the backing dir + metadata.
    _ = ScratchUuid,

    test_helper:cleanup([Pid]),
    io:format("~n=== Test 27 bestanden ===~n~n"),
    halt(0).

%% ---- helpers ------------------------------------------------------

find_by_persist(Records, Persist) ->
    case [R || R <- Records, maps:get(persist, R) =:= Persist] of
        [R | _] -> R;
        []      -> erlang:error({no_record_for_persist, Persist})
    end.
