#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 26: DSL Volume Mount Options — End-to-End
%%
%% Exercises the *DSL path* for mount-options-typed volumes:
%%
%%   hardened_volumes.exs                (Elixir DSL)
%%       | mix run Code.compile_file; mod.write!/1
%%       v
%%   /tmp/erlkoenig_integration_26.term  (Erlang term file)
%%       | erlkoenig_config:parse/1 (patch binary path) + :load/1
%%       v
%%   container(s) running
%%       | inspect ospid → read /proc/<pid>/mountinfo
%%       v
%%   Kernel-side assertions (ro, nosuid, nodev, noexec)
%%
%% Covers:
%%   1. opts: "rw,nosuid,nodev,noexec,relatime" on /uploads — flags land
%%   2. read_only: true on /etc/app — ro bind remount applied
%%   3. Default volume /data — no special flags
%%   4. Writes to ro mount → EROFS
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 26: DSL Volume Mount Options ===~n~n"),
    test_helper:boot(),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/hardened_volumes.exs"),
    TermFile = "/tmp/erlkoenig_integration_26.term",
    DemoBin  = binary_to_list(test_helper:demo("sleeper")),

    %% Host-side volume base — erlkoenig creates per-container subdirs
    %% inside this. We clean it up at the end.
    VolRoot = "/var/lib/erlkoenig/volumes",

    %% --- Step 1: compile DSL .exs → .term -----------------------
    test_helper:step("mix compile hardened_volumes.exs -> .term", fun() ->
        DslDir = filename:join(Root, "dsl"),
        Snippet = io_lib:format(
                    "[{mod, _} | _] = Code.compile_file(~p); "
                    "mod.write!(~p)",
                    [Example, TermFile]),
        Cmd = "cd " ++ DslDir ++
              " && MIX_ENV=test mix run --no-deps-check --no-compile -e " ++
              shell_quote(lists:flatten(Snippet)) ++ " 2>&1",
        Output = os:cmd(Cmd),
        io:format("    ~ts", [Output]),
        case filelib:is_regular(TermFile) of
            true -> ok;
            false -> {error, {term_not_created, Output}}
        end
    end),

    %% --- Step 2: parse + patch binary paths + cut replicas to 1 --
    %% The example uses replicas: 2 for realism, but we only need one
    %% container to verify mount flags. Lower replicas → less noise.
    test_helper:step("parse + patch sleeper + replicas=1", fun() ->
        case erlkoenig_config:parse(TermFile) of
            {ok, Config} ->
                Pods = maps:get(pods, Config, []),
                BinPath = list_to_binary(DemoBin),
                PatchedPods = [patch_pod(P, BinPath) || P <- Pods],
                PatchedConfig = Config#{pods => PatchedPods},
                Formatted = io_lib:format("~tp.~n", [PatchedConfig]),
                ok = file:write_file(TermFile, Formatted),
                Total = lists:sum([length(maps:get(containers, P, []))
                                   || P <- PatchedPods]),
                io:format("    ~p pod(s), ~p container(s) after patch~n",
                          [length(PatchedPods), Total]),
                case Total of
                    N when N > 0 -> ok;
                    _ -> {error, no_containers}
                end;
            {error, Reason} ->
                {error, {parse_failed, Reason}}
        end
    end),

    %% --- Step 3: load config (spawns containers) ----------------
    Pids = test_helper:step("erlkoenig_config:load/1", fun() ->
        case erlkoenig_config:load(TermFile) of
            {ok, Ps} ->
                io:format("    spawned ~p container(s)~n", [length(Ps)]),
                {ok, Ps};
            {error, Reason} ->
                {error, {load_failed, Reason}}
        end
    end),

    timer:sleep(2000),

    %% --- Step 4: Find a running container and read its mountinfo -
    %% There's exactly one container after our patch (replicas=1).
    OsPid = test_helper:step("Inspect container os_pid", fun() ->
        case Pids of
            [P | _] ->
                Info = erlkoenig:inspect(P),
                case maps:get(state, Info, undefined) of
                    running -> {ok, maps:get(os_pid, Info)};
                    State   -> {error, {not_running, State}}
                end;
            [] ->
                {error, no_pids_from_load}
        end
    end),

    MiPath = lists:flatten(io_lib:format("/proc/~p/mountinfo", [OsPid])),

    test_helper:step("/uploads has nosuid+nodev+noexec+relatime", fun() ->
        case find_mount_line(MiPath, " /uploads ") of
            {ok, Line} ->
                io:format("    ~s~n", [Line]),
                assert_flags(Line, ["nosuid", "nodev", "noexec", "relatime"]);
            {error, R} ->
                {error, R}
        end
    end),

    test_helper:step("/etc/app is ro (legacy read_only:true)", fun() ->
        case find_mount_line(MiPath, " /etc/app ") of
            {ok, Line} ->
                io:format("    ~s~n", [Line]),
                assert_flags(Line, ["ro"]);
            {error, R} ->
                {error, R}
        end
    end),

    test_helper:step("/data has no special hardening flags", fun() ->
        case find_mount_line(MiPath, " /data ") of
            {ok, Line} ->
                io:format("    ~s~n", [Line]),
                %% Default mount should NOT carry these kernel flags.
                case [F || F <- ["ro", "nosuid", "nodev", "noexec"],
                           string:find(Line, F) =/= nomatch] of
                    []       -> ok;
                    Unwanted -> {error, {unexpected_flags_on_rw, Unwanted}}
                end;
            {error, R} ->
                {error, R}
        end
    end),

    %% --- Step 5: writes to /etc/app must fail with EROFS --------
    test_helper:step("Write to /etc/app fails with EROFS", fun() ->
        Path = lists:flatten(
            io_lib:format("/proc/~p/root/etc/app/boom.txt", [OsPid])),
        case file:write_file(Path, <<"should-not-succeed">>) of
            {error, erofs} -> ok;
            {error, eacces} -> ok;
            {error, Other} -> {error, {unexpected_errno, Other}};
            ok -> {error, write_succeeded_on_ro}
        end
    end),

    %% --- Cleanup ------------------------------------------------
    test_helper:step("Cleanup containers + term + host vols", fun() ->
        test_helper:cleanup(Pids),
        file:delete(TermFile),
        os:cmd("rm -rf " ++ VolRoot ++ "/web-0-app"),
        ok
    end),

    io:format("~n=== Test 26 bestanden ===~n~n"),
    halt(0).

%% ---- helpers ------------------------------------------------------

%% Replace every container's `binary` + force replicas: 1.
patch_pod(Pod, BinPath) ->
    Containers = maps:get(containers, Pod, []),
    Patched = [C#{binary => BinPath, replicas => 1} || C <- Containers],
    Pod#{containers => Patched}.

find_mount_line(Path, Needle) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            Lines = string:split(binary_to_list(Bin), "\n", all),
            case [L || L <- Lines, string:find(L, Needle) =/= nomatch] of
                []         -> {error, {mount_not_found, Needle}};
                [Line | _] -> {ok, Line}
            end;
        {error, R} ->
            {error, {read_mountinfo_failed, R}}
    end.

assert_flags(Line, Wanted) ->
    case [W || W <- Wanted, string:find(Line, W) =:= nomatch] of
        []      -> ok;
        Missing -> {error, {missing_flags, Missing, Line}}
    end.

shell_quote(S) ->
    Escaped = lists:flatten(
                [case C of
                     $' -> "'\\''";
                     Other -> Other
                 end || C <- S]),
    "'" ++ Escaped ++ "'".
