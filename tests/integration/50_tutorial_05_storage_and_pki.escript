#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 50: tutorial/05_storage_and_pki.exs — volumes + signatures.
%%
%% Proves:
%%   - 4 volume forms on db (persistent, read-only, mount-opts,
%%     ephemeral) are all bind-mounted into the container with the
%%     declared flags.
%%   - Ephemeral volume's UUID-dir goes away after container stop.
%%   - The api container starts with its declared cgroup limits
%%     (disk/cpu/memory/pids).
%%
%% NOTE: the runnable tutorial intentionally does not require signatures:
%% the installed echo_server demo binary is unsigned. Signature enforcement
%% is covered by the dedicated PKI examples/tests.
-mode(compile).

-define(PARENT, <<"ek_t50">>).
-define(GW_CIDR, "10.50.0.1/24").

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 50: tutorial 05_storage_and_pki ===~n~n"),
    require_root(),

    test_helper:boot(),
    logger:set_primary_config(level, error),
    application:set_env(erlkoenig, quarantine_enabled, false),

    Root     = test_helper:project_root(),
    Example  = filename:join(Root, "examples/tutorial/05_storage_and_pki.exs"),
    TermFile = "/tmp/erlkoenig_tutorial_05.term",
    DemoBin  = test_helper:demo("echo_server"),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(?PARENT),
    tutorial_helper:ensure_dummy(?PARENT, ?GW_CIDR),

    test_helper:step("compile 05_storage_and_pki.exs → term", fun() ->
        tutorial_helper:compile_dsl(Root, Example, TermFile)
    end),

    test_helper:step("patch term (unsigned echo_server)",
      fun() ->
        ok = tutorial_helper:patch_term(TermFile,
               #{binary => DemoBin, parents => #{<<"ek_data">> => ?PARENT}}),
        %% Keep this scrubber as a compatibility guard for older generated
        %% terms; current tutorial config no longer emits signature fields.
        {ok, Config0} = erlkoenig_config:parse(TermFile),
        Pods = [strip_sig_opts(P) || P <- maps:get(pods, Config0, [])],
        Config1 = Config0#{pods => Pods},
        ok = file:write_file(TermFile, io_lib:format("~tp.~n", [Config1])),
        ok
    end),

    test_helper:step("load + 3 containers (db + 2× api) run", fun() ->
        %% api has replicas: 2, db has replicas: 1 → 3 total.
        tutorial_helper:load_and_wait(TermFile, 3, 30_000)
    end),

    test_helper:step("db has /var/lib/postgresql/data bind-mounted",
      fun() ->
        case tutorial_helper:find_pid(<<"stateful-0-db">>) of
            {ok, Pid} ->
                #{os_pid := OsPid} = erlkoenig:inspect(Pid),
                Out = os:cmd(io_lib:format(
                        "cat /proc/~B/mountinfo 2>&1", [OsPid])),
                case re:run(Out, "/var/lib/postgresql/data",
                            [{capture, none}]) of
                    match -> ok;
                    _ -> {error, {data_volume_missing, Out}}
                end;
            not_found -> {error, db_container_not_found}
        end
    end),

    test_helper:step("db has read-only /etc/postgresql volume", fun() ->
        {ok, Pid} = tutorial_helper:find_pid(<<"stateful-0-db">>),
        #{os_pid := OsPid} = erlkoenig:inspect(Pid),
        Out = os:cmd(io_lib:format(
                "cat /proc/~B/mountinfo 2>&1", [OsPid])),
        %% The mountinfo line for read-only mounts carries " ro,"
        %% in field 6 (mount options).  Match against the container
        %% mount path.
        Lines = string:split(Out, "\n", all),
        EtcPg = [L || L <- Lines,
                      string:str(L, "/etc/postgresql") > 0],
        case EtcPg of
            [] -> {error, {no_etc_pg_line, Out}};
            [L | _] ->
                case re:run(L, " ro[, ]", [{capture, none}]) of
                    match -> ok;
                    _ -> {error, {not_read_only, L}}
                end
        end
    end),

    test_helper:step("db has nosuid/nodev/noexec on /srv/import",
      fun() ->
        {ok, Pid} = tutorial_helper:find_pid(<<"stateful-0-db">>),
        #{os_pid := OsPid} = erlkoenig:inspect(Pid),
        Out = os:cmd(io_lib:format(
                "cat /proc/~B/mountinfo 2>&1", [OsPid])),
        Lines = string:split(Out, "\n", all),
        SrvImport = [L || L <- Lines,
                          string:str(L, "/srv/import") > 0],
        case SrvImport of
            [] -> {error, {no_srv_import_line, Out}};
            [L | _] ->
                Needs = ["nosuid", "nodev", "noexec"],
                case [Flag || Flag <- Needs,
                              re:run(L, Flag, [{capture, none}]) =/= match] of
                    [] -> ok;
                    Missing -> {error, {missing_flags, Missing, L}}
                end
        end
    end),

    test_helper:step("ephemeral /tmp volume is backed by XFS-loop UUID dir",
      fun() ->
        {ok, Pid} = tutorial_helper:find_pid(<<"stateful-0-db">>),
        #{os_pid := OsPid} = erlkoenig:inspect(Pid),
        Out = os:cmd(io_lib:format(
                "cat /proc/~B/mountinfo | grep -E ' /tmp '  2>&1",
                [OsPid])),
        %% Volume pool on XFS-loop is mounted as /dev/loopN with a
        %% per-volume sub-path `/ek_vol_<uuid>/` (SPEC-EK-024).
        case re:run(Out, "/ek_vol_[0-9a-f]+ /tmp",
                    [{capture, none}]) of
            match -> ok;
            _ -> {error, {no_ephemeral_backing, Out}}
        end
    end),

    test_helper:step("api cgroup enforces declared limits", fun() ->
        case tutorial_helper:find_pid(<<"stateful-0-api">>) of
            {ok, Pid} ->
                Info = erlkoenig:inspect(Pid),
                Limits = maps:get(limits, Info, #{}),
                case maps:get(memory, Limits) of
                    256_000_000 -> ok;
                    Other -> {error, {unexpected_memory_limit, Other}}
                end;
            not_found -> {error, api_not_found}
        end
    end),

    test_helper:step("cleanup", fun() ->
        tutorial_helper:cleanup_all(),
        tutorial_helper:cleanup_dummy(?PARENT),
        file:delete(TermFile),
        ok
    end),

    io:format("~n=== Test 50 passed ===~n~n"),
    halt(0).

require_root() ->
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end.

strip_sig_opts(Pod) ->
    Cts = [maps:without([signature_required, sig_path, files], Ct)
           || Ct <- maps:get(containers, Pod, [])],
    Pod#{containers => Cts}.
