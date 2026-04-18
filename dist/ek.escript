#!/usr/bin/env escript
%%! -hidden -kernel start_distribution false
%%
%% ek — operator CLI for an erlkoenig runtime.
%%
%% Speaks to the local node via Erlang distribution. Reads the cookie
%% from /etc/erlkoenig/cookie by default; override with --cookie-file
%% or the ERLKOENIG_COOKIE_FILE environment variable. The target node
%% defaults to erlkoenig@$(hostname); override with --node.
%%
%% Subcommand grouping mirrors the book chapters: ct (containers),
%% pod, vol (volumes), quarantine, admission, node. Each subcommand
%% calls existing public APIs on the running node and formats the
%% result locally.
%%
%% Output format: --format table (default) | json | plain.
%%

-mode(compile).

%%====================================================================
%% Entry point
%%====================================================================

main(Args) ->
    {Opts, Rest} = parse_global_opts(Args, #{
        format     => table,
        node       => default_target_node(),
        cookie_file => default_cookie_file()
    }),
    case Rest of
        [] -> print_usage(), halt(0);
        ["help" | _] -> print_usage(), halt(0);
        ["--help" | _] -> print_usage(), halt(0);
        ["-h" | _] -> print_usage(), halt(0);
        _ ->
            %% Only set up Erlang distribution for commands that
            %% actually need to talk to a running node. Pure local
            %% transforms (`dsl compile`) work without a cookie or
            %% a target node.
            case needs_distribution(Rest) of
                true  -> ensure_distribution(Opts);
                false -> ok
            end,
            try dispatch(Rest, Opts) of
                ok -> halt(0);
                {error, Msg} -> die(Msg)
            catch
                Class:Reason:Stack ->
                    die(io_lib:format("internal error: ~p:~p~n~p",
                                      [Class, Reason, Stack]))
            end
    end.

%% Commands that work without a running erlkoenig node.
needs_distribution(["dsl" | _]) -> false;
needs_distribution(_)            -> true.

%%====================================================================
%% Dispatch — every subcommand is one clause
%%====================================================================

%% --- Node ---------------------------------------------------------
dispatch(["node", "ping"], O)    -> node_ping(O);
dispatch(["ping"], O)            -> node_ping(O);
dispatch(["node", "version"], O) -> node_version(O);
dispatch(["version"], O)         -> node_version(O);
dispatch(["node", "health"], O)  -> node_health(O);

%% --- Containers ---------------------------------------------------
dispatch(["ct", "list"], O)            -> ct_list(O);
dispatch(["ps"], O)                    -> ct_list(O);  %% docker-familiar alias
dispatch(["ct", "inspect", Name], O)   -> ct_inspect(O, list_to_binary(Name));
dispatch(["ct", "stop",   Name], O)    -> ct_stop(O, list_to_binary(Name));

%% --- Pods ---------------------------------------------------------
dispatch(["pod", "list"], O) -> pod_list(O);

%% --- Stack up / down (compose-style, preferred for operators) ----
%% Accepts .exs (auto-compiled to .term) or .term directly.
dispatch(["up", Path], O)             -> stack_up(O, Path);
dispatch(["down", Path], O)           -> stack_down(O, Path);
dispatch(["down"], O)                 -> stack_down_all(O);

%% --- Config (low-level, still exposed) ---------------------------
dispatch(["config", "validate", Path], O) -> config_validate(O, Path);
dispatch(["config", "load",     Path], O) -> config_load(O, Path);
dispatch(["config", "reload",   Path], O) -> config_reload(O, Path);

%% --- DSL compile (.exs → .term) — uses bundled Elixir ------------
dispatch(["dsl", "compile", Path], _O) ->
    dsl_compile(Path, default_term_path(Path));
dispatch(["dsl", "compile", Path, "-o", Out], _O) ->
    dsl_compile(Path, Out);
dispatch(["dsl", "compile", Path, "--output", Out], _O) ->
    dsl_compile(Path, Out);

%% --- Volumes ------------------------------------------------------
dispatch(["vol", "list"], O)                          -> vol_list(O, all);
dispatch(["vol", "list", "--container", Name], O)     -> vol_list(O, {ct, list_to_binary(Name)});
dispatch(["vol", "inspect", IdOrName], O)             -> vol_inspect(O, IdOrName);
dispatch(["vol", "destroy", Uuid], O)                 -> vol_destroy(O, list_to_binary(Uuid));
dispatch(["vol", "orphans"], O)                       -> vol_orphans(O);
dispatch(["vol", "set-quota", Uuid, Size], O)         -> vol_set_quota(O, list_to_binary(Uuid),
                                                                       list_to_binary(Size));

%% --- Quarantine ---------------------------------------------------
dispatch(["quarantine", "list"], O)                   -> q_list(O);
dispatch(["quarantine", "add", Hash], O)              -> q_add(O, decode_hash(Hash), manual);
dispatch(["quarantine", "add", Hash, "--reason", R], O) -> q_add(O, decode_hash(Hash),
                                                                 list_to_atom(R));
dispatch(["quarantine", "remove", Hash], O)           -> q_remove(O, decode_hash(Hash));

%% --- Admission ----------------------------------------------------
dispatch(["admission", "snapshot"], O) -> adm_snapshot(O);

%% --- Help / unknown ----------------------------------------------
dispatch(Other, _) ->
    die(io_lib:format("unknown command: ~s~n  run `ek help` for usage",
                      [string:join(Other, " ")])).

%%====================================================================
%% Node — basic health
%%====================================================================

node_ping(#{node := Target}) ->
    case net_adm:ping(Target) of
        pong -> emit_plain("pong"), ok;
        pang -> {error, io_lib:format("no response from ~p", [Target])}
    end.

node_version(O) ->
    {ok, Vsn} = call(O, application, get_key, [erlkoenig, vsn]),
    emit_plain(Vsn).

node_health(O) ->
    %% No central health gen_server snapshot yet — surface app uptime
    %% and supervisor child count as a minimal liveness signal.
    Uptime = call(O, erlang, statistics, [wall_clock]),
    {WallMs, _} = Uptime,
    Children = call(O, supervisor, count_children, [erlkoenig_sup]),
    emit(O, [
        {uptime_ms, WallMs},
        {sup_children, proplists:get_value(active, Children)}
    ]).

%%====================================================================
%% Containers
%%====================================================================

ct_list(O) ->
    Pids = call(O, pg, get_members, [erlkoenig_pg, erlkoenig_cts]),
    Rows = [container_row(O, P) || P <- Pids],
    emit_table(O, [name, state, ip, zone, restart_count],
               [row_to_list(R, [name, state, ip, zone, restart_count])
                || R <- Rows]).

ct_inspect(O, Name) ->
    case find_container(O, Name) of
        {ok, Pid} ->
            Info = call(O, erlkoenig, inspect, [Pid]),
            emit(O, maps:to_list(Info));
        not_found ->
            {error, io_lib:format("container '~s' not found", [Name])}
    end.

ct_stop(O, Name) ->
    case find_container(O, Name) of
        {ok, Pid} ->
            ok = call(O, erlkoenig, stop, [Pid]),
            emit_plain(io_lib:format("stopped ~s", [Name]));
        not_found ->
            {error, io_lib:format("container '~s' not found", [Name])}
    end.

container_row(O, Pid) ->
    Info = try call(O, erlkoenig, inspect, [Pid])
           catch _:_ -> #{} end,
    NetInfo = maps:get(net_info, Info, #{}),
    #{
        name          => maps:get(name, Info, atom_to_binary(node(Pid))),
        state         => maps:get(state, Info, unknown),
        ip            => format_ip(maps:get(ip, NetInfo, undefined)),
        zone          => maps:get(zone, Info, default),
        restart_count => maps:get(restart_count, Info, 0)
    }.

find_container(O, Name) ->
    Pids = call(O, pg, get_members, [erlkoenig_pg, erlkoenig_cts]),
    Match = lists:filtermap(
        fun(P) ->
            try
                Info = call(O, erlkoenig, inspect, [P]),
                case maps:get(name, Info, undefined) =:= Name
                     orelse maps:get(id, Info, undefined) =:= Name of
                    true  -> {true, P};
                    false -> false
                end
            catch _:_ -> false
            end
        end, Pids),
    case Match of
        [P | _] -> {ok, P};
        []      -> not_found
    end.

%%====================================================================
%% Config — load / validate / reload .term files
%%====================================================================

config_validate(O, Path) ->
    PathBin = list_to_binary(Path),
    case call(O, erlkoenig_config, validate, [PathBin]) of
        ok ->
            emit_plain(io_lib:format("ok: ~s validates", [Path]));
        {error, Reason} ->
            {error, io_lib:format("validation failed: ~p", [Reason])}
    end.

config_load(O, Path) ->
    PathBin = list_to_binary(Path),
    case call(O, erlkoenig_config, load, [PathBin]) of
        {ok, Results} ->
            Names = [binary_to_list(N) || {N, _P} <- Results],
            emit_plain(io_lib:format("loaded ~p container(s)~n  ~s",
                                     [length(Results),
                                      string:join(Names, ", ")]));
        {error, Reason} ->
            {error, io_lib:format("load failed: ~p", [Reason])}
    end.

config_reload(O, Path) ->
    PathBin = list_to_binary(Path),
    case call(O, erlkoenig_config, reload, [PathBin]) of
        {ok, Pids} ->
            emit_plain(io_lib:format("reloaded; running container(s): ~p",
                                     [length(Pids)]));
        {error, Reason} ->
            {error, io_lib:format("reload failed: ~p", [Reason])}
    end.

%%====================================================================
%% Stack up / down — compose-style operator interface
%%
%% `up`   = validate → (compile if .exs) → load → spawn missing +
%%          restart drifted + stop removed.
%% `down` = read declared names from the file → stop each.
%% `down` (no args) = stop every running container on the node.
%%
%% Accepts .exs (auto-compiled via the bundled Elixir) or .term
%% directly. A mis-typed extension is rejected before touching the node.
%%====================================================================

stack_up(O, Path) ->
    case ensure_term(Path) of
        {error, _} = E -> E;
        {ok, TermPath} ->
            PathBin = list_to_binary(TermPath),
            case call(O, erlkoenig_config, load, [PathBin]) of
                {ok, Results} ->
                    Names = [binary_to_list(N) || {N, _P} <- Results],
                    emit_plain(io_lib:format(
                        "up: ~p container(s) running~n  ~s",
                        [length(Results),
                         case Names of [] -> "(no delta)"; _ -> string:join(Names, ", ") end]));
                {error, Reason} ->
                    {error, io_lib:format("up failed: ~p", [Reason])}
            end
    end.

stack_down(O, Path) ->
    case ensure_term(Path) of
        {error, _} = E -> E;
        {ok, TermPath} ->
            PathBin = list_to_binary(TermPath),
            case call(O, erlkoenig_config, declared_names, [PathBin]) of
                {ok, Names} when Names =/= [] ->
                    Stopped = [stop_silently(O, N) || N <- Names],
                    Count = length([ok || ok <- Stopped]),
                    emit_plain(io_lib:format(
                        "down: stopped ~p/~p container(s)",
                        [Count, length(Names)]));
                {ok, []} ->
                    emit_plain("down: nothing declared in " ++ Path);
                {error, Reason} ->
                    {error, io_lib:format("down failed: ~p", [Reason])}
            end
    end.

stack_down_all(O) ->
    Infos = call(O, erlkoenig_ct, list, []),
    Names = [maps:get(name, I) || I <- Infos, is_map(I)],
    case Names of
        [] ->
            emit_plain("down: nothing running");
        _ ->
            Stopped = [stop_silently(O, binary_to_list(iolist_to_binary(N)))
                       || N <- Names],
            Count = length([ok || ok <- Stopped]),
            emit_plain(io_lib:format(
                "down: stopped ~p/~p container(s)",
                [Count, length(Names)]))
    end.

%% Stop by name; returns `ok' on success, `{error, Reason}' otherwise.
stop_silently(O, Name) when is_list(Name) ->
    stop_silently(O, list_to_binary(Name));
stop_silently(O, NameBin) when is_binary(NameBin) ->
    case find_container(O, NameBin) of
        {ok, Pid} ->
            try call(O, erlkoenig, stop, [Pid]) of
                ok -> ok;
                Other -> {error, Other}
            catch C:E -> {error, {C, E}}
            end;
        not_found ->
            %% Declared but not running — treat as already-down success.
            ok
    end.

%% Given a path ending in .exs, compile to the sibling .term and return
%% its path. Given .term directly, pass through. Otherwise error.
ensure_term(Path) ->
    case filename:extension(Path) of
        ".term" ->
            case filelib:is_regular(Path) of
                true  -> {ok, Path};
                false -> {error, io_lib:format(
                    "file not found: ~s", [Path])}
            end;
        ".exs" ->
            case filelib:is_regular(Path) of
                false -> {error, io_lib:format(
                    "file not found: ~s", [Path])};
                true ->
                    TermPath = default_term_path(Path),
                    case dsl_compile(Path, TermPath) of
                        ok -> {ok, TermPath};
                        {error, _} = E -> E
                    end
            end;
        _ ->
            {error, io_lib:format(
                "expected .exs or .term, got: ~s", [Path])}
    end.

%%====================================================================
%% DSL compile — uses the bundled Elixir runtime
%%
%% No connection to a running node is needed; this is a pure local
%% transform from .exs source to .term artifact. Runs in a fresh
%% short-lived BEAM (Elixir invokes its own erl), so the running
%% erlkoenig instance isn't touched by compiler state.
%%====================================================================

dsl_compile(InputPath, OutputPath) ->
    case locate_elixir_bundle() of
        {error, Reason} -> {error, Reason};
        {ok, BundleRoot} ->
            ElixirBin  = filename:join([BundleRoot, "bin", "elixir"]),
            LibDir     = filename:join(BundleRoot, "lib"),
            ErtsBinDir = locate_erts_bin(),
            BootPath   = locate_start_clean_boot(),
            %% Record the pre-compile mtime so we can tell whether the
            %% Elixir subprocess actually rewrote the file (subprocess
            %% crashes don't guarantee OutputPath is absent — a stale
            %% copy from an earlier run may still be on disk).
            OldMtime = mtime(OutputPath),
            BootFlag = case BootPath of
                undefined -> "";
                P -> io_lib:format("--erl '-boot ~s' ", [P])
            end,
            PathPrefix = case ErtsBinDir of
                undefined -> "";
                D -> io_lib:format("PATH=~s:$PATH ", [D])
            end,
            Cmd = io_lib:format(
                "~s~s "
                %% Boot only kernel+stdlib via start_clean — without
                %% this the default boot loads the full erlkoenig app
                %% and pollutes the compile output with NOTICE REPORTs.
                "~s"
                "-pa ~s/elixir/ebin "
                "-pa ~s/eex/ebin "
                "-pa ~s/logger/ebin "
                "-pa ~s/erlkoenig_dsl/ebin "
                "-e '"
                "case Code.compile_file(System.argv |> hd) do "
                "  [{mod, _} | _] -> mod.write!(System.argv |> tl |> hd); "
                "  _ -> System.halt(2) "
                "end "
                "' "
                "~s ~s 2>&1",
                [PathPrefix, ElixirBin, BootFlag,
                 LibDir, LibDir, LibDir, LibDir,
                 InputPath, OutputPath]),
            Output = os:cmd(lists:flatten(Cmd)),
            NewMtime = mtime(OutputPath),
            case NewMtime =/= none andalso NewMtime =/= OldMtime of
                true ->
                    case string:trim(Output) of
                        "" -> ok;
                        Msg -> io:format("~ts~n", [Msg])  % warnings
                    end,
                    emit_plain(io_lib:format("compiled ~s -> ~s",
                                             [InputPath, OutputPath]));
                false ->
                    {error, io_lib:format(
                        "compile failed (output not written):~n~ts",
                        [Output])}
            end
    end.

%% Find /opt/erlkoenig/erts-VSN/bin next to the release root so that
%% the Elixir wrapper (which uses `erl` from PATH) can locate ERTS.
locate_erts_bin() ->
    ScriptDir = filename:dirname(escript:script_name()),
    Candidates = [
        filename:join([ScriptDir, "..", "erts-*", "bin"]),
        filename:join(["/opt/erlkoenig", "erts-*", "bin"])
    ],
    first_glob(Candidates).

%% Find a usable start_clean.boot (without the ".boot" suffix, as erl expects).
locate_start_clean_boot() ->
    ScriptDir = filename:dirname(escript:script_name()),
    Candidates = [
        filename:join([ScriptDir, "..", "releases", "*", "start_clean.boot"]),
        filename:join(["/opt/erlkoenig", "releases", "*", "start_clean.boot"])
    ],
    case first_glob(Candidates) of
        undefined -> undefined;
        Path      -> filename:rootname(Path)  % strip ".boot" for -boot arg
    end.

first_glob([]) -> undefined;
first_glob([Pattern | Rest]) ->
    case filelib:wildcard(Pattern) of
        []        -> first_glob(Rest);
        [Hit | _] -> Hit
    end.

%% Read mtime field (6) of a file_info record, or 'none' if absent.
mtime(Path) ->
    case file:read_file_info(Path) of
        {ok, Info} -> element(6, Info);
        _          -> none
    end.

%% Try to find the bundled Elixir tree. Two layouts:
%%   1. Installed: /opt/erlkoenig/elixir/{bin,lib}
%%   2. Source:    dist/elixir/{bin,lib}
%% Plus an env override for ad-hoc setups.
locate_elixir_bundle() ->
    Candidates = [
        os:getenv("EK_ELIXIR_HOME"),
        "/opt/erlkoenig/elixir",
        "dist/elixir",
        filename:join(filename:dirname(escript:script_name()), "elixir"),
        filename:join([filename:dirname(escript:script_name()),
                       "..", "elixir"])
    ],
    Found = lists:filter(
        fun(false) -> false;
           (P) -> filelib:is_regular(filename:join([P, "bin", "elixir"]))
        end, Candidates),
    case Found of
        [Path | _] -> {ok, Path};
        [] ->
            {error,
             "no Elixir bundle found — set EK_ELIXIR_HOME or install "
             "the release that ships /opt/erlkoenig/elixir/"}
    end.

%% Default output path: input.exs → input.term in the same directory.
default_term_path(InputPath) ->
    Dir  = filename:dirname(InputPath),
    Base = filename:basename(InputPath, ".exs"),
    filename:join(Dir, Base ++ ".term").

%%====================================================================
%% Pods
%%====================================================================

pod_list(O) ->
    %% Until a public erlkoenig_pod:list/0 lands, derive from the
    %% supervisor children of erlkoenig_pod_sup_sup. Pod name is read
    %% from each supervisor's process label ({erlkoenig_pod, Name}).
    Children = call(O, supervisor, which_children, [erlkoenig_pod_sup_sup]),
    Rows = [pod_row(O, Pid) || {_Id, Pid, _Type, _Mod} <- Children,
                               is_pid(Pid)],
    emit_table(O, [name, pid, children],
               [row_to_list(R, [name, pid, children]) || R <- Rows]).

pod_row(O, Pid) ->
    Name = case call(O, proc_lib, get_label, [Pid]) of
        {erlkoenig_pod, N} -> N;
        _                  -> <<"?">>
    end,
    Kids = try length(call(O, supervisor, which_children, [Pid]))
           catch _:_ -> 0 end,
    #{name => Name, pid => format_pid(Pid), children => Kids}.

%%====================================================================
%% Volumes
%%====================================================================

vol_list(O, Filter) ->
    Records = case Filter of
        all          -> call(O, erlkoenig_volume_store, list, []);
        {ct, Name}   -> call(O, erlkoenig_volume_store, list_by_container, [Name])
    end,
    Rows = [vol_row(R) || R <- Records],
    emit_table(O, [uuid, container, persist, lifecycle, host_path],
               [row_to_list(R, [uuid, container, persist, lifecycle, host_path])
                || R <- Rows]).

vol_row(R) ->
    #{
        uuid      => maps:get(uuid, R),
        container => maps:get(container, R),
        persist   => maps:get(persist, R),
        lifecycle => maps:get(lifecycle, R),
        host_path => maps:get(host_path, R)
    }.

vol_inspect(O, IdOrName) ->
    Records = call(O, erlkoenig_volume_store, list, []),
    Match = case lists:filter(
        fun(R) ->
            UuidMatch = maps:get(uuid, R) =:= list_to_binary(IdOrName),
            NameMatch = atom_to_list(maps:get(persist, R)) =:= IdOrName
                        orelse binary_to_list(maps:get(persist, R)) =:= IdOrName,
            UuidMatch orelse NameMatch
        end, Records) of
        []    -> not_found;
        [V|_] -> V
    end,
    case Match of
        not_found ->
            {error, io_lib:format("volume '~s' not found", [IdOrName])};
        Vol ->
            emit(O, maps:to_list(Vol))
    end.

vol_destroy(O, Uuid) ->
    case call(O, erlkoenig_volume_store, destroy, [Uuid]) of
        ok ->
            emit_plain(io_lib:format("destroyed ~s", [Uuid]));
        {error, not_found} ->
            {error, io_lib:format("volume '~s' not found", [Uuid])};
        {error, Reason} ->
            {error, io_lib:format("destroy failed: ~p", [Reason])}
    end.

vol_orphans(O) ->
    %% An orphan is a UUID-named directory under volumes_root with
    %% no matching metadata record.
    Root = call(O, erlkoenig_volume_store, volumes_root, []),
    Records = call(O, erlkoenig_volume_store, list, []),
    Known = sets:from_list([maps:get(uuid, R) || R <- Records],
                           [{version, 2}]),
    case call(O, file, list_dir, [binary_to_list(Root)]) of
        {ok, Entries} ->
            Orphans = [E || E <- Entries,
                            string:prefix(E, "ek_vol_") =/= nomatch,
                            not sets:is_element(list_to_binary(E), Known)],
            emit_table(O, [uuid],
                       [[U] || U <- Orphans]);
        {error, Reason} ->
            {error, io_lib:format("can't read ~s: ~p", [Root, Reason])}
    end.

vol_set_quota(O, Uuid, Size) ->
    case call(O, erlkoenig_volume_store, set_quota, [Uuid, Size]) of
        {ok, _Updated} ->
            emit_plain(io_lib:format("quota set on ~s to ~s", [Uuid, Size]));
        {error, not_found} ->
            {error, io_lib:format("volume '~s' not found", [Uuid])};
        {error, Reason} ->
            {error, io_lib:format("set_quota failed: ~p", [Reason])}
    end.

%%====================================================================
%% Quarantine
%%====================================================================

q_list(O) ->
    Entries = call(O, erlkoenig_quarantine, list, []),
    Rows = [#{
        hash   => hex(Hash),
        reason => format_term(maps:get(reason, Meta)),
        since  => format_ts(maps:get(since, Meta))
    } || {Hash, Meta} <- Entries],
    emit_table(O, [hash, reason, since],
               [row_to_list(R, [hash, reason, since]) || R <- Rows]).

q_add(O, Hash, Reason) ->
    ok = call(O, erlkoenig_quarantine, quarantine, [Hash, Reason]),
    emit_plain(io_lib:format("quarantined ~s", [hex(Hash)])).

q_remove(O, Hash) ->
    ok = call(O, erlkoenig_quarantine, unquarantine, [Hash]),
    emit_plain(io_lib:format("unquarantined ~s", [hex(Hash)])).

%%====================================================================
%% Admission
%%====================================================================

adm_snapshot(O) ->
    Snap = call(O, erlkoenig_admission, snapshot, []),
    HostInFlight  = maps:get(host_in_flight, Snap),
    Queued        = maps:get(queued, Snap),
    ZoneInFlight  = maps:get(zone_in_flight, Snap),
    emit_plain(io_lib:format("host_in_flight: ~p~nqueued: ~p~nzone_in_flight: ~p",
                             [HostInFlight, Queued, ZoneInFlight])).

%%====================================================================
%% Distribution + RPC
%%====================================================================

ensure_distribution(#{cookie_file := CookiePath, node := TargetNode}) ->
    case file:read_file(CookiePath) of
        {ok, CookieBin} ->
            Cookie = list_to_atom(string:trim(binary_to_list(CookieBin))),
            CtlNodeName = list_to_atom(
                "ek_" ++ os:getpid() ++ "@" ++ short_host()),
            {ok, _} = net_kernel:start([CtlNodeName, shortnames]),
            true = erlang:set_cookie(node(), Cookie),
            case net_adm:ping(TargetNode) of
                pong -> ok;
                pang ->
                    die(io_lib:format(
                        "can't reach erlkoenig at ~p — is the service running?",
                        [TargetNode]))
            end;
        {error, Reason} ->
            die(io_lib:format("can't read cookie ~s: ~p", [CookiePath, Reason]))
    end.

call(#{node := Target}, Module, Function, Args) ->
    case rpc:call(Target, Module, Function, Args, 30_000) of
        {badrpc, {'EXIT', {undef, _}}} ->
            die(io_lib:format(
                "remote call ~p:~p/~p is undef on ~p — release may be older "
                "than this CLI, or the module isn't loaded",
                [Module, Function, length(Args), Target]));
        {badrpc, nodedown} ->
            die(io_lib:format("node ~p is down", [Target]));
        {badrpc, {'EXIT', {timeout, _}}} ->
            die(io_lib:format("timeout calling ~p:~p on ~p",
                              [Module, Function, Target]));
        {badrpc, Reason} ->
            die(io_lib:format("RPC ~p:~p failed: ~p",
                              [Module, Function, Reason]));
        Result ->
            Result
    end.

short_host() ->
    {ok, Host} = inet:gethostname(),
    Host.

default_target_node() ->
    {ok, Host} = inet:gethostname(),
    list_to_atom("erlkoenig@" ++ Host).

default_cookie_file() ->
    case os:getenv("ERLKOENIG_COOKIE_FILE") of
        false ->
            %% Try the canonical install paths in order. The relx
            %% release writes its cookie to /opt/erlkoenig/cookie;
            %% /etc/erlkoenig/cookie is an older convention some
            %% installers used.
            Candidates = ["/opt/erlkoenig/cookie",
                          "/etc/erlkoenig/cookie"],
            case lists:filter(fun filelib:is_regular/1, Candidates) of
                [P | _] -> P;
                []      -> hd(Candidates)  %% best guess for error msg
            end;
        Path -> Path
    end.

%%====================================================================
%% Argument parsing
%%====================================================================

parse_global_opts(["--node", Node | Rest], Acc) ->
    parse_global_opts(Rest, Acc#{node => list_to_atom(Node)});
parse_global_opts(["--cookie-file", Path | Rest], Acc) ->
    parse_global_opts(Rest, Acc#{cookie_file => Path});
parse_global_opts(["--format", Fmt | Rest], Acc) ->
    parse_global_opts(Rest, Acc#{format => list_to_atom(Fmt)});
parse_global_opts([Arg | Rest], Acc) when is_list(Arg) ->
    %% Also accept --key=value form for shell-friendly invocations.
    case string:split(Arg, "=") of
        ["--node", V]        -> parse_global_opts(Rest, Acc#{node => list_to_atom(V)});
        ["--cookie-file", V] -> parse_global_opts(Rest, Acc#{cookie_file => V});
        ["--format", V]      -> parse_global_opts(Rest, Acc#{format => list_to_atom(V)});
        _                    -> {Acc, [Arg | Rest]}
    end;
parse_global_opts([], Acc) ->
    {Acc, []}.

%%====================================================================
%% Output formatting
%%====================================================================

emit_plain(IOData) -> io:format("~ts~n", [IOData]).

emit(#{format := json}, KVs) when is_list(KVs) ->
    Map = maps:from_list([{to_key(K), to_jsonable(V)} || {K, V} <- KVs]),
    io:format("~ts~n", [json:encode(Map)]);
emit(_, KVs) when is_list(KVs) ->
    Width = lists:max([byte_size(to_key(K)) || {K, _} <- KVs] ++ [0]),
    lists:foreach(
        fun({K, V}) ->
            io:format("~-*ts  ~ts~n", [Width, to_key(K), to_value(V)])
        end, KVs).

emit_table(#{format := json}, Headers, Rows) ->
    Records = [maps:from_list(lists:zip(Headers, Row)) || Row <- Rows],
    JsonReady = [maps:map(fun(_, V) -> to_jsonable(V) end, R) || R <- Records],
    io:format("~ts~n", [json:encode(JsonReady)]);
emit_table(#{format := plain}, _Headers, Rows) ->
    lists:foreach(
        fun(Row) ->
            io:format("~ts~n",
                      [string:join([to_value(V) || V <- Row], "\t")])
        end, Rows);
emit_table(_, Headers, Rows) ->
    HeaderStrs = [atom_to_list(H) || H <- Headers],
    StringRows = [[to_value(V) || V <- Row] || Row <- Rows],
    Widths = column_widths([HeaderStrs | StringRows]),
    print_row(HeaderStrs, Widths),
    print_row([lists:duplicate(W, $-) || W <- Widths], Widths),
    [print_row(R, Widths) || R <- StringRows],
    ok.

print_row(Row, Widths) ->
    Padded = lists:zipwith(
        fun(V, W) -> string:left(to_string(V), W, $\s) end,
        Row, Widths),
    io:format("~ts~n", [string:join(Padded, "  ")]).

column_widths(Rows) ->
    Cols = transpose(Rows),
    [lists:max([length(to_string(C)) || C <- Col]) || Col <- Cols].

transpose([])      -> [];
transpose([[] | _]) -> [];
transpose(M) ->
    [[hd(R) || R <- M] | transpose([tl(R) || R <- M])].

row_to_list(Map, Keys) -> [maps:get(K, Map) || K <- Keys].

to_string(V) when is_list(V)    -> V;
to_string(V) when is_binary(V)  -> binary_to_list(V);
to_string(V) when is_atom(V)    -> atom_to_list(V);
to_string(V) when is_integer(V) -> integer_to_list(V);
to_string(V)                    -> lists:flatten(io_lib:format("~p", [V])).

to_value(V) -> to_string(V).

to_key(K) when is_atom(K)   -> atom_to_binary(K, utf8);
to_key(K) when is_binary(K) -> K;
to_key(K)                   -> iolist_to_binary(io_lib:format("~p", [K])).

to_jsonable(V) when is_atom(V), V =/= true, V =/= false, V =/= null ->
    atom_to_binary(V, utf8);
to_jsonable(V) when is_pid(V) -> iolist_to_binary(pid_to_list(V));
to_jsonable(V) when is_reference(V) -> iolist_to_binary(ref_to_list(V));
to_jsonable(V) when is_tuple(V) ->
    iolist_to_binary(io_lib:format("~p", [V]));
to_jsonable(V) when is_map(V) ->
    maps:map(fun(_, X) -> to_jsonable(X) end, V);
to_jsonable(V) when is_list(V) ->
    case io_lib:char_list(V) of
        true  -> list_to_binary(V);
        false -> [to_jsonable(X) || X <- V]
    end;
to_jsonable(V) -> V.

format_ip(undefined) -> "-";
format_ip({A, B, C, D}) ->
    io_lib:format("~B.~B.~B.~B", [A, B, C, D]).

format_pid(Pid) when is_pid(Pid) -> pid_to_list(Pid);
format_pid(Other)                -> io_lib:format("~p", [Other]).

format_ts(Ms) when is_integer(Ms) ->
    Sec = Ms div 1000,
    {{Y, Mo, D}, {H, Mi, S}} = calendar:system_time_to_universal_time(Sec, second),
    io_lib:format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ",
                  [Y, Mo, D, H, Mi, S]);
format_ts(Other) -> io_lib:format("~p", [Other]).

format_term(T) when is_atom(T) -> atom_to_list(T);
format_term(T)                 -> lists:flatten(io_lib:format("~p", [T])).

hex(Bin) when is_binary(Bin), byte_size(Bin) >= 8 ->
    binary:encode_hex(Bin);
hex(Other) ->
    io_lib:format("~p", [Other]).

decode_hash(Str) when is_list(Str) ->
    decode_hash(list_to_binary(Str));
decode_hash(Bin) when is_binary(Bin) ->
    try binary:decode_hex(Bin) of
        Raw when byte_size(Raw) =:= 32 -> Raw;
        _ -> die("quarantine hash must be 64 hex chars (SHA-256)")
    catch _:_ -> die("quarantine hash must be hex-encoded")
    end.

%%====================================================================
%% Help / fatal errors
%%====================================================================

print_usage() ->
    io:format(
        "ek — operator CLI for an erlkoenig runtime~n"
        "~n"
        "Usage:~n"
        "  ek [global-options] <area> <command> [args...]~n"
        "~n"
        "Global options:~n"
        "  --node <name>        Target node (default: erlkoenig@$hostname)~n"
        "  --cookie-file <path> Cookie file (default: /etc/erlkoenig/cookie)~n"
        "  --format <fmt>       Output format: table | json | plain (default: table)~n"
        "~n"
        "Areas and commands:~n"
        "  node ping            Liveness check~n"
        "  node version         App version~n"
        "  node health          Uptime + supervisor child count~n"
        "~n"
        "  up <file>            Start a stack (accepts .exs or .term)~n"
        "  down <file>          Stop containers declared in <file>~n"
        "  down                 Stop every running container~n"
        "~n"
        "  ps                   Alias for `ct list`~n"
        "  ct list              All running containers~n"
        "  ct inspect <name>    Full state of one container~n"
        "  ct stop <name>       Send stop signal to one container~n"
        "~n"
        "  pod list             All pod supervisors~n"
        "~n"
        "  config validate <file.term>          Parse + validate a term file~n"
        "  config load     <file.term>          Low-level: same as `up` but no .exs~n"
        "  config reload   <file.term>          Low-level: apply delta against live state~n"
        "~n"
        "  dsl compile <file.exs> [-o <file>]   Compile DSL to .term (uses bundled Elixir)~n"
        "~n"
        "  vol list [--container <name>]      Volumes (optionally filtered)~n"
        "  vol inspect <uuid|persist-name>    Volume metadata~n"
        "  vol destroy <uuid>                 Remove metadata + on-disk dir~n"
        "  vol orphans                        UUID dirs without metadata~n"
        "  vol set-quota <uuid> <size>        Set XFS project quota (e.g. 1G)~n"
        "~n"
        "  quarantine list                    Currently quarantined hashes~n"
        "  quarantine add <hash> [--reason X] Manually quarantine~n"
        "  quarantine remove <hash>           Lift a quarantine~n"
        "~n"
        "  admission snapshot                 Spawn-gate state~n"
        "~n"
        "Examples:~n"
        "  ek up my_stack.exs~n"
        "  ek ps~n"
        "  ek down my_stack.term~n"
        "  ek --format json vol list~n"
        "  ek quarantine add deadbeef00112233 --reason operator_ban~n"
        ).

die(Msg) ->
    io:format(standard_error, "error: ~ts~n", [Msg]),
    halt(1).
