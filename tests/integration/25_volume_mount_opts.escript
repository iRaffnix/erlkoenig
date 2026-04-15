#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 25: Volume Mount Options (ro, nosuid, noexec, propagation)
%%
%% Tests the full mount-options pipeline:
%%   DSL `opts:` string → erlkoenig_mount_opts parse → extended wire
%%   TLV → C runtime ek_bind_mount_volume → actual kernel mount.
%%
%% Covers:
%%   1. opts: "ro" produces a read-only mount (write → EROFS)
%%   2. opts: "ro,nosuid,nodev,noexec" all land as kernel MS_* flags
%%      (verified by parsing /proc/<pid>/mountinfo inside the container)
%%   3. Legacy `read_only: true` still works (back-compat)
%%   4. `opts:` wins when both are given (opts: "rw" + read_only: true
%%      ⇒ mount is rw, not ro)
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 25: Volume Mount Options ===~n~n"),
    test_helper:boot(),

    VolBase = "/var/lib/erlkoenig/volumes/test-mount-opts",
    HardenedDir = VolBase ++ "/hardened",
    RwDir = VolBase ++ "/rw-wins",
    LegacyDir = VolBase ++ "/legacy-ro",
    lists:foreach(
        fun(D) -> filelib:ensure_dir(D ++ "/"), file:make_dir(D) end,
        [VolBase, HardenedDir, RwDir, LegacyDir]),

    %% Seed a file inside each source dir so we can test reads/writes.
    ok = file:write_file(HardenedDir ++ "/probe.txt", <<"hardened\n">>),
    ok = file:write_file(RwDir ++ "/probe.txt", <<"rw\n">>),
    ok = file:write_file(LegacyDir ++ "/probe.txt", <<"legacy\n">>),

    %% --- Test 1: opts: "ro,nosuid,nodev,noexec" ---
    Pid1 = test_helper:step(
        "Spawn container with hardened mount opts", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("sleeper"),
            #{ip => {10,0,0,10},
              args => [<<"60">>],
              name => <<"test-mount-opts-1">>,
              volumes => [
                  #{container => <<"/hardened">>,
                    persist => <<"hardened">>,
                    opts => <<"ro,nosuid,nodev,noexec">>}
              ]}),
        timer:sleep(1500),
        {ok, P}
    end),

    test_helper:step("Verify mount flags visible in mountinfo", fun() ->
        Info = erlkoenig:inspect(Pid1),
        OsPid = maps:get(os_pid, Info),
        MiPath = io_lib:format("/proc/~p/mountinfo", [OsPid]),
        {ok, Mi} = file:read_file(lists:flatten(MiPath)),
        Lines = string:split(binary_to_list(Mi), "\n", all),
        case [L || L <- Lines, string:find(L, " /hardened ") =/= nomatch] of
            [] -> {error, no_hardened_mount};
            [Line | _] ->
                Wanted = ["ro", "nosuid", "nodev", "noexec"],
                Missing = [W || W <- Wanted,
                                string:find(Line, W) =:= nomatch],
                case Missing of
                    [] ->
                        io:format("    mountinfo: ~s~n", [Line]),
                        ok;
                    _ ->
                        {error, {missing_flags, Missing, Line}}
                end
        end
    end),

    test_helper:step("Write to hardened mount must fail with EROFS", fun() ->
        Info = erlkoenig:inspect(Pid1),
        OsPid = maps:get(os_pid, Info),
        Path = lists:flatten(
            io_lib:format("/proc/~p/root/hardened/attempt.txt", [OsPid])),
        case file:write_file(Path, <<"should-fail">>) of
            {error, erofs} -> ok;
            {error, eacces} -> ok;
            {error, Other} -> {error, {unexpected_errno, Other}};
            ok -> {error, write_succeeded_on_ro_mount}
        end
    end),

    test_helper:cleanup([Pid1]),

    %% --- Test 2: opts wins over read_only ---
    Pid2 = test_helper:step(
        "Spawn with opts: \"rw\" + read_only: true (opts wins)", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("sleeper"),
            #{ip => {10,0,0,11},
              args => [<<"60">>],
              name => <<"test-mount-opts-2">>,
              volumes => [
                  #{container => <<"/rw">>,
                    persist => <<"rw-wins">>,
                    opts => <<"rw">>,
                    read_only => true}
              ]}),
        timer:sleep(1500),
        {ok, P}
    end),

    test_helper:step("Mount is rw despite legacy flag", fun() ->
        Info = erlkoenig:inspect(Pid2),
        OsPid = maps:get(os_pid, Info),
        Path = lists:flatten(
            io_lib:format("/proc/~p/root/rw/probe.txt", [OsPid])),
        %% Append a line — only works if the mount is actually rw.
        case file:write_file(Path, <<"appended\n">>, [append]) of
            ok -> ok;
            {error, R} -> {error, {write_failed, R}}
        end
    end),

    test_helper:cleanup([Pid2]),

    %% --- Test 3: legacy read_only: true still works ---
    Pid3 = test_helper:step(
        "Spawn with legacy read_only: true (no opts: string)", fun() ->
        {ok, P} = erlkoenig:spawn(test_helper:demo("sleeper"),
            #{ip => {10,0,0,12},
              args => [<<"60">>],
              name => <<"test-mount-opts-3">>,
              volumes => [
                  #{container => <<"/legacy">>,
                    persist => <<"legacy-ro">>,
                    read_only => true}
              ]}),
        timer:sleep(1500),
        {ok, P}
    end),

    test_helper:step("Legacy ro mount rejects writes", fun() ->
        Info = erlkoenig:inspect(Pid3),
        OsPid = maps:get(os_pid, Info),
        Path = lists:flatten(
            io_lib:format("/proc/~p/root/legacy/new.txt", [OsPid])),
        case file:write_file(Path, <<"should-fail">>) of
            {error, erofs}  -> ok;
            {error, eacces} -> ok;
            {error, Other}  -> {error, {unexpected, Other}};
            ok -> {error, write_succeeded}
        end
    end),

    test_helper:cleanup([Pid3]),

    os:cmd("rm -rf " ++ VolBase),
    io:format("~n=== Test 25 bestanden ===~n~n"),
    halt(0).
