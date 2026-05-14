#!/usr/bin/env escript
%%! -hidden -kernel start_distribution false
%%
%% ek — operator CLI for an erlkoenig runtime.
%%
%% Speaks to the local node via Erlang distribution. Resolves the cookie
%% from ERLKOENIG_COOKIE_FILE, /etc/erlkoenig/cookie, then
%% ~/.config/erlkoenig/cookie; override with --cookie-file. The target node
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

-define(EK_VERSION, "0.9.0").

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
        ["version" | _] -> cli_version(Opts);
        ["--version" | _] -> cli_version(Opts);
        ["-V" | _] -> cli_version(Opts);
        ["--help" | _] -> print_usage(), halt(0);
        ["-h" | _] -> print_usage(), halt(0);
        _ ->
            try dispatch(Rest, Opts) of
                ok -> halt(0);
                {error, Msg} -> die(error, Msg)
            catch
                Class:Reason:Stack ->
                    die(error, io_lib:format("internal error: ~p:~p~n~p",
                                             [Class, Reason, Stack]))
            end
    end.

%%====================================================================
%% Dispatch — every subcommand is one clause
%%====================================================================

%% --- Node ---------------------------------------------------------
dispatch(["node", "ping"], O)    -> node_ping(O);
dispatch(["ping"], O)            -> node_ping(O);
dispatch(["node", "version"], O) -> node_version(O);
dispatch(["node", "health"], O)  -> node_health(O);

%% --- Local diagnostics -------------------------------------------
dispatch(["doctor"], O)          -> doctor(O);
dispatch(["explain", "--list"], O) -> explain_list(O, all);
dispatch(["explain", "--component", Component], O) ->
    explain_list(O, {component, Component});
dispatch(["explain", Code], O)   -> explain(O, Code);

%% --- Containers ---------------------------------------------------
dispatch(["ct", "list"], O)            -> ct_list(O);
dispatch(["ps"], O)                    -> ct_list(O);  %% docker-familiar alias
dispatch(["ct", "inspect", Name], O)   -> ct_inspect(O, list_to_binary(Name));
dispatch(["inspect", Name], O)         -> ct_inspect(O, list_to_binary(Name));
dispatch(["ct", "stop",   Name], O)    -> ct_stop(O, list_to_binary(Name));
dispatch(["stop", Name], O)            -> ct_stop(O, list_to_binary(Name));

%% --- Pods ---------------------------------------------------------
dispatch(["pod", "list"], O) -> pod_list(O);

%% --- Stack up / down (compose-style, preferred for operators) ----
%% Accepts .exs (auto-compiled to .term) or .term directly.
dispatch(["up", Path], O)             -> stack_up(O, Path);
dispatch(["down", Path], O)           -> stack_down(O, Path);
dispatch(["down"], O)                 -> stack_down_no_args(O);

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
dispatch(["vol", "gc-orphans"], O)                    -> vol_gc_orphans(O);
dispatch(["vol", "set-quota", Uuid, Size], O)         -> vol_set_quota(O, list_to_binary(Uuid),
                                                                       list_to_binary(Size));

%% --- Quarantine ---------------------------------------------------
dispatch(["quarantine", "list"], O)                   -> q_list(O);
dispatch(["quarantine", "add", Hash], O)              -> q_add(O, normalize_hash(Hash), manual);
dispatch(["quarantine", "add", Hash, "--reason", R], O) -> q_add(O, normalize_hash(Hash),
                                                                 list_to_atom(R));
dispatch(["quarantine", "remove", Hash], O)           -> q_remove(O, normalize_hash(Hash));

%% --- Admission ----------------------------------------------------
dispatch(["admission", "snapshot"], O) -> adm_snapshot(O);

%% --- NFT ----------------------------------------------------------
dispatch(["nft", "counters"], O) -> nft_counters(O);

%% --- Interactive firewall ----------------------------------------
dispatch(["firewall", "status"], O) -> firewall_status(O);
dispatch(["firewall", "events"], O) -> firewall_events(O);
dispatch(["firewall", "watch"], O)  -> firewall_watch(O);

%% --- Help / unknown ----------------------------------------------
dispatch(Other, _) ->
    die(usage, io_lib:format("unknown command: ~s~n  run `ek help` for usage",
                             [string:join(Other, " ")])).

%%====================================================================
%% Node — basic health
%%====================================================================

cli_version(#{format := json}) ->
    io:format("~ts~n", [json:encode(#{version => <<?EK_VERSION>>})]),
    halt(0);
cli_version(_O) ->
    emit_plain("ek " ?EK_VERSION),
    halt(0).

node_ping(#{node := Target} = O) ->
    ensure_distribution(O),
    case net_adm:ping(Target) of
        pong -> emit_plain("pong"), ok;
        pang -> {error, io_lib:format("no response from ~p", [Target])}
    end.

node_version(O) ->
    {ok, Vsn} = call(O, application, get_key, [erlkoenig, vsn]),
    case maps:get(format, O, table) of
        json -> emit_json(#{<<"version">> => to_str_or_null(Vsn)});
        _    -> emit_plain(Vsn)
    end.

node_health(O) ->
    case op_call(O, node_health, []) of
        {ok, Health} ->
            case maps:get(format, O, table) of
                json -> emit_json(to_json(node_health, Health));
                _    -> emit(O, maps:to_list(Health))
            end;
        {error, Err} ->
            die_operator(Err)
    end.

%%====================================================================
%% Local diagnostics
%%====================================================================

doctor(O) ->
    Catalog = read_error_catalog(),
    Checks = doctor_checks(O, Catalog),
    Fails = [C || C <- Checks, maps:get(status, C) =:= fail],
    case maps:get(format, O, table) of
        json ->
            emit_table(O, [check, status, code, detail, action, evidence],
                       [[maps:get(check, C), maps:get(status, C),
                         maps:get(code, C), maps:get(detail, C),
                         maps:get(action, C), maps:get(evidence, C, #{})]
                        || C <- Checks]),
            case Fails of
                [] -> ok;
                _  -> {error, io_lib:format(
                          "doctor: ~p blocking issue(s)", [length(Fails)])}
            end;
        _ ->
            emit_table(O, [check, status, code, detail, action],
                       [[maps:get(check, C), maps:get(status, C),
                         maps:get(code, C), maps:get(detail, C),
                         maps:get(action, C)] || C <- Checks]),
            case Fails of
                [] -> emit_plain("doctor: no blocking local issues found");
                _  -> {error, io_lib:format(
                          "doctor: ~p blocking issue(s)", [length(Fails)])}
            end
    end.

doctor_checks(O, Catalog) ->
    [
        doctor_probe(runtime_binary, host, runtime_binary_missing,
                     find_runtime_binary(), Catalog),
        doctor_probe(cookie, host, cookie_missing,
                     find_cookie_file(O), Catalog),
        doctor_probe(cookie_permissions, host, cookie_permissions_weak,
                     check_cookie_permissions(O), Catalog),
        doctor_probe(cookie_symlink, host, cookie_symlink_invalid,
                     check_cookie_symlink(O), Catalog),
        doctor_probe(systemd_unit, host, systemd_unit_missing,
                     check_systemd_unit(), Catalog),
        doctor_probe(epmd_local_bind, host, epmd_local_bind_missing,
                     check_epmd_local_bind(), Catalog),
        doctor_probe(node_ping, host, node_ping_failed,
                     check_node_ping(O), Catalog),
        doctor_probe(socket_dir, host, socket_dir_missing,
                     find_socket_dir(), Catalog),
        doctor_probe(cgroup_v2, host, cgroup_v2_missing,
                     check_cgroup_v2(), Catalog),
        doctor_probe(nft, host, nft_missing,
                     check_nft(), Catalog),
        doctor_probe(protocol_vectors, host, protocol_vectors_missing,
                     check_protocol_vectors(), Catalog)
    ].

doctor_probe(Name, _Component, _Reason, {ok, Detail}, _Catalog) ->
    #{check => Name, status => ok, code => "-",
      detail => Detail, action => "-", evidence => #{}};
doctor_probe(Name, Component, Reason, {Status, Evidence}, Catalog)
  when Status =:= fail; Status =:= warn ->
    Code = diagnostic_code(Component, Reason),
    Info = catalog_info(Code, Catalog),
    #{check => Name,
      status => Status,
      code => Code,
      detail => maps:get(description, Info, "(uncataloged)"),
      action => maps:get(operator_action, Info, "-"),
      evidence => Evidence}.

diagnostic_code(Component, Reason) ->
    "EK_" ++ string:uppercase(atom_to_list(Component)) ++
    "_" ++ string:uppercase(atom_to_list(Reason)).

catalog_info(Code, {ok, Entries}) ->
    case lists:filter(fun({EntryCode, _}) ->
                              atom_to_list(EntryCode) =:= Code
                      end, Entries) of
        [{_, Info} | _] -> Info;
        []              -> #{}
    end;
catalog_info(_Code, {error, _}) ->
    #{}.

find_runtime_binary() ->
    Candidates = [
        os:getenv("ERLKOENIG_RT"),
        "/opt/erlkoenig/rt/erlkoenig_rt",
        "/usr/lib/erlkoenig/erlkoenig_rt",
        "../erlkoenig_rt/build/release/erlkoenig_rt"
    ],
    Paths = [P || P <- Candidates, P =/= false],
    case first_regular(Paths) of
        undefined -> {fail, #{paths_searched => Paths}};
        Path      -> {ok, Path}
    end.

find_cookie_file(O) ->
    %% Respect --cookie-file when the operator overrides it; without
    %% this the doctor probes the default path even though the
    %% remote-call paths use the override, which makes "cookie ok"
    %% misleading for `ek --cookie-file X doctor`.
    Path = maps:get(cookie_file, O, default_cookie_file()),
    case filelib:is_regular(Path) of
        true  -> {ok, Path};
        false -> {fail, #{path => Path}}
    end.

check_cookie_permissions(O) ->
    Path = maps:get(cookie_file, O, default_cookie_file()),
    case file:read_file_info(Path) of
        {ok, FileInfo} when element(3, FileInfo) =:= regular ->
            Size = element(2, FileInfo),
            Mode0 = element(8, FileInfo),
            Mode = Mode0 band 8#777,
            Weak = cookie_mode_weak(Mode),
            case {Size > 0, Weak} of
                {true, false} ->
                    {ok, Path ++ " mode " ++ mode_octal(Mode)};
                _ ->
                    {fail, #{path => Path,
                             mode => mode_octal(Mode),
                             size => Size,
                             world_readable => (Mode band 8#004) =/= 0,
                             group_writable => (Mode band 8#020) =/= 0,
                             world_writable => (Mode band 8#002) =/= 0}}
            end;
        {ok, FileInfo} ->
            Type = element(3, FileInfo),
            {fail, #{path => Path, type => Type}};
        {error, Reason} ->
            {fail, #{path => Path, reason => Reason}}
    end.

cookie_mode_weak(Mode) ->
    %% Erlang distribution rejects cookies that are accessible by
    %% other users. We also reject group/world write because it makes
    %% the node identity mutable by more than the service owner.
    (Mode band 8#007) =/= 0 orelse (Mode band 8#020) =/= 0.

check_cookie_symlink(O) ->
    CookiePath = maps:get(cookie_file, O, default_cookie_file()),
    Canonical = "/etc/erlkoenig/cookie",
    Legacy = "/opt/erlkoenig/cookie",
    case CookiePath of
        Canonical ->
            check_cookie_symlink(Canonical, Legacy);
        _ ->
            {ok, "custom cookie file " ++ CookiePath ++
                 " (legacy symlink check skipped)"}
    end.

check_cookie_symlink(Canonical, Legacy) ->
    case file:read_link(Legacy) of
        {ok, Canonical} ->
            case {file:read_file(Canonical), file:read_file(Legacy)} of
                {{ok, Cookie}, {ok, Cookie}} ->
                    {ok, Legacy ++ " -> " ++ Canonical};
                {{ok, _}, {ok, _}} ->
                    {fail, #{legacy => Legacy,
                             canonical => Canonical,
                             reason => content_mismatch}};
                {{error, Reason}, _} ->
                    {fail, #{legacy => Legacy,
                             canonical => Canonical,
                             reason => Reason}};
                {_, {error, Reason}} ->
                    {fail, #{legacy => Legacy,
                             canonical => Canonical,
                             reason => Reason}}
            end;
        {ok, Other} ->
            {fail, #{legacy => Legacy,
                     canonical => Canonical,
                     target => Other}};
        {error, einval} ->
            {fail, #{legacy => Legacy,
                     canonical => Canonical,
                     reason => not_a_symlink}};
        {error, Reason} ->
            {fail, #{legacy => Legacy,
                     canonical => Canonical,
                     reason => Reason}}
    end.

check_systemd_unit() ->
    Path = "/etc/systemd/system/erlkoenig.service",
    case file:read_file_info(Path) of
        {ok, FileInfo} ->
            case element(3, FileInfo) of
                regular -> {ok, Path};
                symlink -> {ok, Path};
                Type    -> {fail, #{path => Path, type => Type}}
            end;
        {error, Reason} ->
            {fail, #{path => Path, reason => Reason}}
    end.

check_epmd_local_bind() ->
    Path = "/etc/systemd/system/erlkoenig.service",
    case file:read_file(Path) of
        {ok, Bin} ->
            case binary:match(Bin, <<"ERL_EPMD_ADDRESS=127.0.0.1">>) of
                nomatch -> {fail, #{path => Path, expected => "ERL_EPMD_ADDRESS=127.0.0.1"}};
                _       -> {ok, "ERL_EPMD_ADDRESS=127.0.0.1"}
            end;
        {error, Reason} ->
            {fail, #{path => Path, reason => Reason}}
    end.

check_node_ping(#{cookie_file := CookiePath, node := TargetNode}) ->
    case start_distribution_probe(CookiePath, TargetNode) of
        ok ->
            case net_adm:ping(TargetNode) of
                pong -> {ok, atom_to_list(TargetNode)};
                pang -> {fail, #{node => TargetNode, reason => pang}}
            end;
        {error, Evidence} ->
            {fail, Evidence}
    end.

start_distribution_probe(CookiePath, TargetNode) ->
    case file:read_file(CookiePath) of
        {ok, CookieBin} ->
            case string:trim(binary_to_list(CookieBin)) of
                "" ->
                    {error, #{cookie_file => CookiePath, reason => empty_cookie}};
                CookieStr ->
                    maybe_start_distribution_probe(CookiePath, TargetNode, CookieStr)
            end;
        {error, Reason} ->
            {error, #{cookie_file => CookiePath, reason => Reason}}
    end.

maybe_start_distribution_probe(CookiePath, TargetNode, CookieStr) ->
    try
        Cookie = list_to_atom(CookieStr),
        case node() of
            nonode@nohost ->
                CtlNodeName = list_to_atom(
                    "ek_doctor_" ++ os:getpid() ++ "@" ++ short_host()),
                case net_kernel:start([CtlNodeName, shortnames]) of
                    {ok, _} -> ok;
                    {error, {already_started, _}} -> ok;
                    {error, Reason} ->
                        throw({probe_error, #{cookie_file => CookiePath,
                                              node => TargetNode,
                                              reason => Reason}})
                end;
            _ ->
                ok
        end,
        true = erlang:set_cookie(node(), Cookie),
        ok
    catch
        throw:{probe_error, Evidence} ->
            {error, Evidence};
        Class:ProbeReason ->
            {error, #{cookie_file => CookiePath,
                      node => TargetNode,
                      reason => io_lib:format("~p:~p", [Class, ProbeReason])}}
    end.

find_socket_dir() ->
    Candidates = ["/run/erlkoenig/containers", "/run/erlkoenig"],
    case lists:filter(fun filelib:is_dir/1, Candidates) of
        [Path | _] -> {ok, Path};
        []         -> {fail, #{paths_searched => Candidates}}
    end.

check_cgroup_v2() ->
    Path = "/sys/fs/cgroup/cgroup.controllers",
    case filelib:is_regular(Path) of
        true  -> {ok, Path};
        false -> {fail, #{path => Path}}
    end.

check_nft() ->
    case os:find_executable("nft") of
        false -> {fail, #{executable => "nft"}};
        Path  -> {ok, Path}
    end.

check_protocol_vectors() ->
    case os:getenv("ERLKOENIG_PROTOCOL_VECTORS") of
        false ->
            {warn, #{env => "ERLKOENIG_PROTOCOL_VECTORS"}};
        Path ->
            case filelib:is_dir(Path) of
                true  -> {ok, Path};
                false -> {warn, #{env => "ERLKOENIG_PROTOCOL_VECTORS", path => Path}}
            end
    end.

mode_octal(Mode) ->
    "0" ++ integer_to_list(Mode, 8).

first_regular([]) -> undefined;
first_regular([Path | Rest]) ->
    case filelib:is_regular(Path) of
        true  -> Path;
        false -> first_regular(Rest)
    end.

explain(O, Code0) ->
    Code = normalize_error_code(Code0),
    case lookup_error_catalog(Code) of
        {error, not_found} ->
            {error, io_lib:format("unknown error code: ~s", [Code0])};
        {error, {catalog_unavailable, Reason}} ->
            {error, io_lib:format("error catalog unavailable: ~p", [Reason])};
        {ok, Info} ->
            emit_explain(O, Code, Info)
    end.

explain_list(O, Filter) ->
    case read_error_catalog() of
        {ok, Entries} ->
            Rows = [explain_list_row(Code, Info)
                    || {Code, Info} <- Entries,
                       explain_entry_matches(Filter, Info)],
            emit_table(O, [code, component, severity, description], Rows);
        {error, Reason} ->
            {error, io_lib:format("error catalog unavailable: ~p", [Reason])}
    end.

explain_entry_matches(all, _Info) ->
    true;
explain_entry_matches({component, Component0}, Info) ->
    Component = string:lowercase(Component0),
    to_value(maps:get(component, Info, unknown)) =:= Component.

explain_list_row(Code, Info) ->
    [
        atom_to_list(Code),
        maps:get(component, Info, unknown),
        maps:get(severity, Info, error),
        maps:get(description, Info, "")
    ].

normalize_error_code(Code) ->
    Upper = string:uppercase(Code),
    case string:prefix(Upper, "EK_") of
        nomatch -> "EK_" ++ Upper;
        _       -> Upper
    end.

lookup_error_catalog(Code) ->
    case read_error_catalog() of
        {ok, Entries} ->
            case lists:filter(fun({EntryCode, _}) ->
                                      atom_to_list(EntryCode) =:= Code
                              end, Entries) of
                [{_, Info} | _] -> {ok, Info};
                []              -> {error, not_found}
            end;
        {error, Reason} ->
            {error, {catalog_unavailable, Reason}}
    end.

read_error_catalog() ->
    case first_regular(error_catalog_candidates()) of
        undefined ->
            {error, not_found};
        Path ->
            case file:consult(Path) of
                {ok, [Entries]} when is_list(Entries) -> {ok, Entries};
                {ok, Other}                           -> {error, {bad_catalog, Path, Other}};
                {error, Reason}                       -> {error, {read_failed, Path, Reason}}
            end
    end.

error_catalog_candidates() ->
    ScriptDir = filename:dirname(filename:absname(escript:script_name())),
    [
        filename:join([ScriptDir, "error_catalog.term"]),
        filename:join([ScriptDir, "..", "share", "error_catalog.term"]),
        filename:join([ScriptDir, "..", "lib", "erlkoenig", "priv", "error_catalog.term"]),
        filename:join(["apps", "erlkoenig", "priv", "error_catalog.term"]),
        filename:join(["priv", "error_catalog.term"])
    ].

emit_explain(#{format := json} = O, Code, Info) ->
    emit(O, maps:to_list(Info#{code => Code}));
emit_explain(_, Code, Info) ->
    io:format("~ts  [since ~ts]~n",
              [Code, to_value(maps:get(since, Info, "unknown"))]),
    io:format("component: ~ts~n", [to_value(maps:get(component, Info, unknown))]),
    io:format("severity:  ~ts~n~n", [to_value(maps:get(severity, Info, error))]),
    print_explain_block("description", maps:get(description, Info, "")),
    print_explain_block("operator action", maps:get(operator_action, Info, "")),
    print_explain_list("evidence fields you will see",
                       maps:get(evidence_fields, Info, [])),
    print_explain_list("related", maps:get(related_specs, Info, [])),
    case maps:find(iron_rule, Info) of
        {ok, IronRule} -> print_explain_block("iron rule", IronRule);
        error          -> ok
    end,
    ok.

print_explain_block(_Label, "") ->
    ok;
print_explain_block(Label, Text) ->
    io:format("~ts:~n  ~ts~n~n", [Label, to_value(Text)]).

print_explain_list(_Label, []) ->
    ok;
print_explain_list(Label, Values) ->
    Joined = string:join([to_value(V) || V <- Values], ", "),
    io:format("~ts:~n  ~ts~n~n", [Label, Joined]).

%%====================================================================
%% Containers
%%====================================================================

ct_list(O) ->
    Infos = operator_value(O, container_list, []),
    case maps:get(format, O, table) of
        json ->
            emit_json([to_json(container_summary, I) || I <- Infos]);
        _ ->
            Rows = [container_row(Info) || Info <- Infos],
            emit_table(O, [name, state, ip, zone, restart_count],
                       [row_to_list(R, [name, state, ip, zone, restart_count])
                        || R <- Rows])
    end.

ct_inspect(O, Name) ->
    case op_call(O, container_inspect, [Name]) of
        {ok, Info} ->
            Timeline = lifecycle_timeline(Info),
            case maps:get(format, O, table) of
                json ->
                    emit_json(to_json(container_info,
                                      Info#{timeline => Timeline}));
                _ ->
                    emit(O, maps:to_list(Info)),
                    print_timeline(Timeline),
                    ok
            end;
        {error, Err} ->
            die_operator(Err)
    end.

lifecycle_timeline(Info) ->
    State = maps:get(state, Info, unknown),
    Error = maps:get(error, Info, undefined),
    Exit = maps:get(exit_info, Info, undefined),
    [
        timeline_step(runtime_socket, socket_state(Info)),
        timeline_step(handshake, handshake_state(Info)),
        timeline_step(spawn, spawn_state(Info)),
        timeline_step(network, network_state(Info)),
        timeline_step(container, State),
        timeline_step(exit, exit_state(Exit)),
        timeline_step(error, error_state(Error))
    ].

timeline_step(Name, Status) ->
    #{step => Name, status => Status}.

socket_state(Info) ->
    case maps:get(socket_path, Info, undefined) of
        undefined -> unknown;
        _         -> configured
    end.

handshake_state(Info) ->
    case maps:get(handshake, Info, undefined) of
        true      -> ok;
        false     -> pending;
        undefined -> unknown
    end.



spawn_state(Info) ->
    case maps:get(os_pid, Info, undefined) of
        Pid when is_integer(Pid), Pid > 0 -> spawned;
        _ -> pending
    end.

network_state(Info) ->
    case maps:get(net_info, Info, undefined) of
        Net when is_map(Net), map_size(Net) > 0 -> configured;
        _ -> pending
    end.

exit_state(undefined) -> none;
exit_state(Exit) when is_map(Exit) -> exited;
exit_state(_) -> unknown.

error_state(undefined) -> none;
error_state(_) -> present.

print_timeline(Timeline) ->
    io:format("~nTimeline~n"),
    lists:foreach(
        fun(#{step := Step, status := Status}) ->
            io:format("  ~-16s ~s~n", [atom_to_list(Step), to_value(Status)])
        end, Timeline).

ct_stop(O, Name) ->
    case op_call(O, container_stop, [Name]) of
        ok ->
            emit_plain(io_lib:format("stopped ~s", [Name]));
        {error, Err} ->
            die_operator(Err)
    end.

container_row(Info) ->
    NetInfo = maps:get(net_info, Info, #{}),
    #{
        name          => maps:get(name, Info, maps:get(id, Info, <<"?">>)),
        state         => maps:get(state, Info, unknown),
        ip            => format_ip(maps:get(ip, NetInfo, undefined)),
        zone          => maps:get(zone, Info, default),
        restart_count => maps:get(restart_count, Info, 0)
    }.

%%====================================================================
%% Config — load / validate / reload .term files
%%====================================================================

config_validate(O, Path) ->
    PathBin = list_to_binary(Path),
    case call(O, erlkoenig_config, validate, [PathBin]) of
        ok ->
            emit_plain(io_lib:format("ok: ~s validates", [Path]));
        {error, Reason} ->
            {error, io_lib:format("validation failed: ~s",
                                  [format_config_error(Reason)])}
    end.

%% Map common erlkoenig_config error shapes to operator-friendly
%% strings. Falls back to ~p only for unrecognized shapes.
format_config_error({read_failed, File, {Line, erl_parse, _}}) ->
    io_lib:format("parse error in ~s at line ~p", [bin_or_str(File), Line]);
format_config_error({read_failed, File, enoent}) ->
    io_lib:format("file not found: ~s", [bin_or_str(File)]);
format_config_error({read_failed, File, eacces}) ->
    io_lib:format("permission denied: ~s", [bin_or_str(File)]);
format_config_error({read_failed, File, Reason}) ->
    io_lib:format("could not read ~s: ~p", [bin_or_str(File), Reason]);
format_config_error({invalid_format, File}) ->
    io_lib:format("file is empty or not a single Erlang term: ~s",
                  [bin_or_str(File)]);
format_config_error({missing_field, Field}) ->
    io_lib:format("missing required field: ~p", [Field]);
format_config_error({invalid_field, Field, Value}) ->
    io_lib:format("invalid value for ~p: ~p", [Field, Value]);
format_config_error(Other) ->
    io_lib:format("~p", [Other]).

bin_or_str(B) when is_binary(B) -> binary_to_list(B);
bin_or_str(S) when is_list(S)   -> S;
bin_or_str(O)                   -> io_lib:format("~p", [O]).

config_load(O, Path) ->
    PathBin = list_to_binary(Path),
    case call(O, erlkoenig_config, load, load_args(PathBin, O)) of
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

%% Build the RPC arg-list for erlkoenig_config:load — `load/1' default,
%% `load/2' only when --allow-lockout is set. Keeps backward
%% compatibility: an old daemon without `load/2' still answers `load/1'
%% calls when the operator did not pass --allow-lockout.
load_args(PathBin, O) ->
    case maps:get(allow_lockout, O, false) of
        true  -> [PathBin, #{allow_lockout => true}];
        false -> [PathBin]
    end.

stack_up(O, Path) ->
    case ensure_term(Path) of
        {error, _} = E -> E;
        {ok, TermPath} ->
            PathBin = list_to_binary(TermPath),
            case call(O, erlkoenig_config, load, load_args(PathBin, O)) of
                {ok, Results} ->
                    Names = [binary_to_list(N) || {N, _P} <- Results],
                    %% load/1 returns containers it tried to spawn —
                    %% but a container with a missing binary still
                    %% gets a gen_statem; it then crashes in `creating`.
                    %% Briefly let the system settle, then report based
                    %% on actual state instead of trusting the load
                    %% return shape.
                    timer:sleep(500),
                    Statuses = [{N, container_post_up_info(O, N)} || N <- Names],
                    Policies = read_declared_policies(TermPath),
                    Classified = [{N, maps:get(state, Info),
                                   classify_post_up(N, maps:get(state, Info),
                                                    Policies, Info),
                                   Info}
                                  || {N, Info} <- Statuses],
                    Running   = [N || {N, _, running, _} <- Classified],
                    Completed = [{N, S} || {N, S, completed, _} <- Classified],
                    Failed    = [{N, S, Info} || {N, S, failed, Info} <- Classified],
                    Total     = length(Names),
                    case Failed of
                        [] ->
                            CompletedNote = case Completed of
                                [] -> "";
                                _  -> io_lib:format("; ~p completed (transient/temporary)",
                                                    [length(Completed)])
                            end,
                            emit_plain(io_lib:format(
                                "up: ~p/~p container(s) running~s~n  ~s",
                                [length(Running), Total, CompletedNote,
                                 case Names of
                                     [] -> "(no delta)";
                                     _  -> string:join(Names, ", ")
                                 end]));
                        _ ->
                            FailedSummary = string:join(
                                [format_post_up_failure(N, S, Info)
                                 || {N, S, Info} <- Failed], ", "),
                            die(error, io_lib:format(
                                "up: ~p/~p container(s) running; failed: ~s",
                                [length(Running), Total, FailedSummary]))
                    end;
                {error, Reason} ->
                    {error, io_lib:format("up failed: ~p", [Reason])}
            end
    end.

%% Classify each container's post-load state against its declared restart
%% policy so legitimate one-shots (transient + clean-exit, temporary +
%% any-exit) do not get mis-flagged as failures.
classify_post_up(_Name, State, _Policies, _Info) when State =:= running;
                                                        State =:= namespace_ready;
                                                        State =:= creating;
                                                        State =:= restarting ->
    running;
classify_post_up(Name, State, Policies, Info) ->
    Policy = maps:get(Name, Policies, undefined),
    case has_quarantine_refusal(Info) of
        true ->
            failed;
        false ->
            case State of
                gone ->
                    case policy_tolerates_clean_terminal(Policy) of
                        true  -> completed;
                        false -> failed
                    end;
                stopped ->
                    case policy_tolerates_clean_terminal(Policy) of
                        true  -> completed;
                        false -> failed
                    end;
                failed ->
                    %% A `failed' state at settle time is only a legitimate
                    %% completion for explicit one-shot policies (temporary /
                    %% no_restart). For `transient' (on_failure), it indicates
                    %% an abnormal terminal failure — quarantine, repeated
                    %% setup error, or hit restart-attempt limit — that the
                    %% operator should see in the up summary.
                    case policy_tolerates_failed_terminal(Policy) of
                        true  -> completed;
                        false -> failed
                    end;
                _ ->
                    failed
            end
    end.

has_quarantine_refusal(#{error := Error}) when is_map(Error) ->
    is_quarantine_refusal(Error);
has_quarantine_refusal(_) ->
    false.

is_quarantine_refusal(#{code := Code}) ->
    Code =:= 'EK_RUNTIME_BINARY_QUARANTINED'
        orelse Code =:= <<"EK_RUNTIME_BINARY_QUARANTINED">>
        orelse Code =:= "EK_RUNTIME_BINARY_QUARANTINED";
is_quarantine_refusal(_) ->
    false.

%% Policies under which `stopped' or `gone' at settle time is a
%% legitimate completion (clean exit, or auto_shutdown removing a
%% pod whose only child terminated cleanly). `permanent'/`always'
%% deliberately do NOT qualify — any non-running state for them is
%% a failure.
policy_tolerates_clean_terminal(undefined)        -> false;
policy_tolerates_clean_terminal(permanent)        -> false;
policy_tolerates_clean_terminal(always)           -> false;
policy_tolerates_clean_terminal({always, _})      -> false;
policy_tolerates_clean_terminal(_)                -> true.

%% Policies under which a terminal `failed' state is a legitimate
%% completion (explicit one-shot workloads). `transient' is
%% intentionally excluded so genuine terminal failures (quarantine,
%% setup errors, restart-limit hits) still surface in `ek up' output.
policy_tolerates_failed_terminal(temporary)       -> true;
policy_tolerates_failed_terminal(no_restart)      -> true;
policy_tolerates_failed_terminal(_)               -> false.

%% Parse the .term config to build a `#{ResolvedName => RestartPolicy}'
%% lookup. Mirrors the resolution rule in erlkoenig_config_flatten:
%% `<PodName>-<ReplicaIdx>-<CtName>' for pod-supervised containers.
%% Returns an empty map if anything goes wrong — the caller falls back
%% to the conservative classification.
read_declared_policies(TermPath) ->
    try
        case file:consult(TermPath) of
            {ok, [Config]} when is_map(Config) ->
                Pods = maps:get(pods, Config, []),
                FromPods = lists:foldl(fun pod_policies/2, #{}, Pods),
                %% Legacy flat `containers' key (no pods).
                FlatCts = maps:get(containers, Config, []),
                lists:foldl(fun(Ct, Acc) ->
                    Name = name_to_str(maps:get(name, Ct, <<>>)),
                    Restart = maps:get(restart, Ct, no_restart),
                    Acc#{Name => Restart}
                end, FromPods, FlatCts);
            _ ->
                #{}
        end
    catch _:_ -> #{}
    end.

pod_policies(Pod, Acc) ->
    PodName = name_to_str(maps:get(name, Pod, <<>>)),
    Cts = maps:get(containers, Pod, []),
    lists:foldl(fun(Ct, A) ->
        CtName   = name_to_str(maps:get(name, Ct, <<>>)),
        Replicas = maps:get(replicas, Ct, 1),
        Restart  = maps:get(restart, Ct, no_restart),
        lists:foldl(fun(Idx, A2) ->
            Resolved = lists:flatten(
                io_lib:format("~s-~w-~s", [PodName, Idx, CtName])),
            A2#{Resolved => Restart}
        end, A, lists:seq(0, Replicas - 1))
    end, Acc, Cts).

name_to_str(N) when is_binary(N) -> binary_to_list(N);
name_to_str(N) when is_list(N)   -> N;
name_to_str(N) when is_atom(N)   -> atom_to_list(N).

container_post_up_info(O, Name) ->
    NameBin = list_to_binary(Name),
    case op_call(O, container_inspect, [NameBin]) of
        {ok, #{state := S} = Info} ->
            #{state => S, error => maps:get(error, Info, undefined)};
        {error, #{code := 'EK_OPERATOR_NOT_FOUND'}} ->
            #{state => gone, error => undefined};
        {error, Err} ->
            #{state => unknown, error => Err}
    end.

format_post_up_failure(Name, State, Info) ->
    Base = lists:flatten(io_lib:format("~s (~s)",
                                       [Name, atom_to_list(State)])),
    case maps:get(error, Info, undefined) of
        undefined ->
            Base;
        Error ->
            Base ++ ": " ++ lists:flatten(io_lib:format("~p", [Error]))
    end.

stack_down(O, Path) ->
    case ensure_term(Path) of
        {error, _} = E -> E;
        {ok, TermPath} ->
            PathBin = list_to_binary(TermPath),
            case call(O, erlkoenig_config, declared_names, [PathBin]) of
                {ok, Names} when Names =/= [] ->
                    Stopped = stop_many_silently(O, Names),
                    Count = length([ok || ok <- Stopped]),
                    case call(O, erlkoenig_config, unload, [PathBin]) of
                        {ok, _} ->
                            emit_plain(io_lib:format(
                                "down: stopped ~p/~p container(s)",
                                [Count, length(Names)]));
                        {error, Reason} ->
                            {error, io_lib:format(
                                "down unload failed after stopping ~p/~p container(s): ~p",
                                [Count, length(Names), Reason])}
                    end;
                {ok, []} ->
                    case call(O, erlkoenig_config, unload, [PathBin]) of
                        {ok, _} ->
                            emit_plain("down: nothing declared in " ++ Path);
                        {error, Reason} ->
                            {error, io_lib:format("down unload failed: ~p", [Reason])}
                    end;
                {error, Reason} ->
                    {error, io_lib:format("down failed: ~p", [Reason])}
            end
    end.

stack_down_all(O) ->
    Infos = operator_value(O, container_list, []),
    Names = [maps:get(name, I) || I <- Infos, is_map(I)],
    case Names of
        [] ->
            emit_plain("down: nothing running");
        _ ->
            Total = length(Names),
            Stopped = stop_many_silently(O, Names),
            Count = length([ok || ok <- Stopped]),
            case Count =:= Total of
                true ->
                    emit_plain(io_lib:format(
                        "down: stopped ~p/~p container(s)",
                        [Count, Total]));
                false ->
                    die(error, io_lib:format(
                        "down --all stopped ~p/~p container(s); ~p failed",
                        [Count, Total, Total - Count]))
            end
    end.

stack_down_no_args(O) ->
    case maps:get(all, O, false) of
        true ->
            stack_down_all(O);
        false ->
            die(usage, "down requires a .term/.exs file or --all")
    end.

%% Stop all requested containers concurrently for real RPC calls. The
%% stopped state machine may wait up to stop_timeout before force-kill;
%% doing that serially turns N containers into N * stop_timeout. Mock mode
%% stays serial because the file-backed mock call log is intentionally simple.
stop_many_silently(O, Names) ->
    Normalized = [normalize_stop_name(N) || N <- Names],
    case os:getenv("ERLKOENIG_EK_MOCK_OPERATOR_API") of
        false ->
            Parent = self(),
            Refs = [begin
                        Ref = make_ref(),
                        spawn_link(fun() ->
                            Parent ! {Ref, stop_silently(O, Name)}
                        end),
                        Ref
                    end || Name <- Normalized],
            [receive
                 {Ref, Result} -> Result
             after 35_000 ->
                 {error, stop_timeout}
             end || Ref <- Refs];
        _Path ->
            [stop_silently(O, Name) || Name <- Normalized]
    end.

normalize_stop_name(Name) when is_binary(Name) ->
    Name;
normalize_stop_name(Name) when is_list(Name) ->
    list_to_binary(Name);
normalize_stop_name(Name) ->
    iolist_to_binary(Name).

%% Stop by name; returns `ok' on success, `{error, Reason}' otherwise.
stop_silently(O, Name) when is_list(Name) ->
    stop_silently(O, list_to_binary(Name));
stop_silently(O, NameBin) when is_binary(NameBin) ->
    case op_call(O, container_stop, [NameBin]) of
        ok ->
            ok;
        {error, #{code := 'EK_OPERATOR_NOT_FOUND'}} ->
            %% Declared but not running — treat as already-down success.
            ok;
        {error, Err} ->
            {error, Err}
    end.

%% Given a path ending in .exs, compile to the sibling .term and return
%% its path. Given .term directly, pass through. Otherwise error.
%%
%% File-not-found cases die with exit 3 (not_found) per the CLI exit
%% contract. Other errors return {error, Msg} for the caller to surface.
ensure_term(Path) ->
    case filename:extension(Path) of
        ".term" ->
            case filelib:is_regular(Path) of
                true  -> {ok, Path};
                false -> die(not_found,
                             io_lib:format("file not found: ~s", [Path]))
            end;
        ".exs" ->
            case filelib:is_regular(Path) of
                false -> die(not_found,
                             io_lib:format("file not found: ~s", [Path]));
                true ->
                    TermPath = default_term_path(Path),
                    case dsl_compile(Path, TermPath) of
                        ok -> {ok, TermPath};
                        {error, _} = E -> E
                    end
            end;
        _ ->
            die(usage,
                io_lib:format("expected .exs or .term, got: ~s", [Path]))
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
    Function = case maps:get(all, O, false) of
        true  -> pod_list_all;
        false -> pod_list
    end,
    case op_call(O, Function, []) of
        {ok, Rows} ->
            case maps:get(format, O, table) of
                json ->
                    emit_json([to_json(pod, R) || R <- Rows]);
                _ ->
                    emit_table(O, [name, pid, children],
                               [row_to_list(R, [name, pid, children])
                                || R <- Rows])
            end;
        {error, Err} ->
            die_operator(Err)
    end.

%%====================================================================
%% Volumes
%%====================================================================

vol_list(O, Filter) ->
    Records = case Filter of
        all ->
            operator_value(O, volume_list, []);
        {ct, Name} ->
            operator_value(O, volume_list_by_container, [Name])
    end,
    case maps:get(format, O, table) of
        json ->
            emit_json([to_json(volume, R) || R <- Records]);
        _ ->
            Rows = [vol_row(R) || R <- Records],
            emit_table(O, [uuid, container, persist, lifecycle, host_path],
                       [row_to_list(R, [uuid, container, persist, lifecycle, host_path])
                        || R <- Rows])
    end.

vol_row(R) ->
    #{
        uuid      => maps:get(uuid, R),
        container => maps:get(container, R),
        persist   => maps:get(persist, R),
        lifecycle => maps:get(lifecycle, R),
        host_path => maps:get(host_path, R)
    }.

vol_inspect(O, IdOrName) ->
    case op_call(O, volume_inspect, [list_to_binary(IdOrName)]) of
        {ok, M} ->
            case maps:get(format, O, table) of
                json -> emit_json(to_json(volume, M));
                _    -> emit(O, maps:to_list(M))
            end;
        {error, Err} ->
            die_operator(Err)
    end.

vol_destroy(O, Uuid) ->
    case maps:get(yes, O, false) of
        true ->
            case op_call(O, volume_destroy, [Uuid]) of
                ok ->
                    emit_plain(io_lib:format("destroyed ~s", [Uuid]));
                {error, Err} ->
                    die_operator(Err)
            end;
        false ->
            die(usage, "vol destroy requires --yes to confirm")
    end.

vol_orphans(O) ->
    case op_call(O, volume_orphans, []) of
        {ok, Orphans} ->
            case maps:get(format, O, table) of
                json ->
                    emit_json([#{<<"uuid">> => to_str_or_null(U)}
                               || U <- Orphans]);
                _ ->
                    emit_table(O, [uuid], [[U] || U <- Orphans])
            end;
        {error, Err} ->
            die_operator(Err)
    end.

%% `ek vol gc-orphans' — physically remove disk-orphan volume
%% directories (i.e. dirs under the volumes root with no DETS
%% record). Mirrors the `vol orphans' read-only discovery
%% counterpart but is destructive, so requires either
%% `--dry-run' (preview only) or `--yes' (commit).
vol_gc_orphans(O) ->
    DryRun = maps:get(dry_run, O, false),
    Yes    = maps:get(yes, O, false),
    case {DryRun, Yes} of
        {true, _} -> do_vol_gc_orphans(O, dry_run);
        {_, true} -> do_vol_gc_orphans(O, confirm);
        _ ->
            die(usage,
                "vol gc-orphans requires --dry-run (preview) or --yes (commit)")
    end.

do_vol_gc_orphans(O, Mode) ->
    case op_call(O, volume_gc_orphans, [Mode]) of
        {ok, Results} ->
            emit_gc_orphans_output(O, Results),
            %% Non-zero exit if any orphan failed during a confirm
            %% run. dry_run never fails — it's pure observation.
            case any_failed(Results) of
                false -> ok;
                true  -> die(error, "vol gc-orphans: one or more deletions failed")
            end;
        {error, Err} ->
            die_operator(Err)
    end.

emit_gc_orphans_output(O, Results) ->
    case maps:get(format, O, table) of
        json ->
            emit_json([gc_result_to_json(R) || R <- Results]);
        _ ->
            emit_table(O,
                       [uuid, mode, status, reason],
                       [[get_or(uuid, R, <<>>),
                         get_or(mode, R, <<>>),
                         get_or(status, R, <<>>),
                         null_to_dash(get_or(reason, R, null))]
                        || R <- Results])
    end.

gc_result_to_json(R) when is_map(R) ->
    #{<<"uuid">>   => to_str_or_null(maps:get(uuid, R, undefined)),
      <<"path">>   => to_str_or_null(maps:get(path, R, undefined)),
      <<"mode">>   => to_str_or_null(maps:get(mode, R, undefined)),
      <<"status">> => to_str_or_null(maps:get(status, R, undefined)),
      <<"reason">> => to_str_or_null(maps:get(reason, R, undefined))}.

any_failed(Results) ->
    lists:any(fun(R) -> maps:get(status, R, undefined) =:= <<"failed">> end,
              Results).

get_or(Key, Map, Default) ->
    case maps:find(Key, Map) of
        {ok, V} -> V;
        error   -> Default
    end.

null_to_dash(null)         -> <<"-">>;
null_to_dash(undefined)    -> <<"-">>;
null_to_dash(<<>>)         -> <<"-">>;
null_to_dash(Other)        -> Other.

vol_set_quota(O, Uuid, Size) ->
    case op_call(O, volume_set_quota, [Uuid, Size]) of
        {ok, _Updated} ->
            emit_plain(io_lib:format("quota set on ~s to ~s", [Uuid, Size]));
        {error, Err} ->
            die_operator(Err)
    end.

%%====================================================================
%% Quarantine
%%====================================================================

q_list(O) ->
    Entries = operator_value(O, quarantine_list, []),
    case maps:get(format, O, table) of
        json ->
            emit_json([to_json(quarantine_entry, E) || E <- Entries]);
        _ ->
            Rows = [#{
                hash   => maps:get(hash, E),
                reason => format_term(maps:get(reason, E)),
                since  => format_ts(maps:get(since, E))
            } || E <- Entries],
            emit_table(O, [hash, reason, since],
                       [row_to_list(R, [hash, reason, since]) || R <- Rows])
    end.

q_add(O, Hash, Reason) ->
    case op_call(O, quarantine_add, [Hash, Reason]) of
        ok -> emit_plain(io_lib:format("quarantined ~s", [Hash]));
        {error, Err} -> die_operator(Err)
    end.

q_remove(O, Hash) ->
    case op_call(O, quarantine_remove, [Hash]) of
        ok -> emit_plain(io_lib:format("unquarantined ~s", [Hash]));
        {error, Err} -> die_operator(Err)
    end.

%%====================================================================
%% Admission
%%====================================================================

adm_snapshot(O) ->
    Snap = operator_value(O, admission_snapshot, []),
    case maps:get(format, O, table) of
        json ->
            emit_json(to_json(admission_snapshot, Snap));
        _ ->
            HostInFlight = maps:get(host_in_flight, Snap),
            Queued       = maps:get(queued, Snap),
            ZoneInFlight = maps:get(zone_in_flight, Snap),
            emit_plain(io_lib:format(
                "host_in_flight: ~p~nqueued: ~p~nzone_in_flight: ~p",
                [HostInFlight, Queued, ZoneInFlight]))
    end.

%%====================================================================
%% NFT
%%====================================================================

nft_counters(O) ->
    Rows = operator_value(O, nft_counters, []),
    case maps:get(format, O, table) of
        json ->
            emit_json([to_json(nft_counter, R) || R <- Rows]);
        _ ->
            emit_table(O,
                       [table, name, packets, bytes, total_packets,
                        total_bytes, pps, bps, interval],
                       [nft_counter_row(R) || R <- Rows])
    end.

nft_counter_row(R) ->
    [maps:get(table, R, <<"-">>),
     maps:get(name, R, <<"-">>),
     maps:get(packets, R, 0),
     maps:get(bytes, R, 0),
     maps:get(total_packets, R, maps:get(packets, R, 0)),
     maps:get(total_bytes, R, maps:get(bytes, R, 0)),
     maps:get(pps, R, 0),
     maps:get(bps, R, 0),
     maps:get(interval, R, 0)].

%%====================================================================
%% Interactive firewall
%%====================================================================

firewall_status(O) ->
    case op_call(O, firewall_status, []) of
        {ok, Status} ->
            case maps:get(format, O, table) of
                json -> emit_json(to_json(firewall_status, Status));
                _    -> emit_firewall_status(Status)
            end;
        {error, Err} ->
            die_operator(Err)
    end.

firewall_events(O) ->
    Limit = maps:get(limit, O, 50),
    case op_call(O, firewall_events, [Limit]) of
        {ok, Events} ->
            case maps:get(format, O, table) of
                json -> emit_json([to_json(firewall_event, E) || E <- Events]);
                _    -> emit_firewall_events(O, Events)
            end;
        {error, Err} ->
            die_operator(Err)
    end.

firewall_watch(O) ->
    Limit = maps:get(limit, O, 50),
    case op_call(O, firewall_events_since, [0, 0, Limit]) of
        {ok, #{cursor := Cursor0, events := Events0}} ->
            PrintedHeader = emit_firewall_event_stream(O, Events0, false),
            firewall_watch_loop(O, Cursor0, Limit, PrintedHeader);
        {error, Err} ->
            die_operator(Err)
    end.

firewall_watch_loop(O, Cursor, Limit, PrintedHeader0) ->
    case op_call(O, firewall_events_since, [Cursor, 1000, Limit]) of
        {ok, #{cursor := Cursor1, events := Events}} ->
            PrintedHeader = emit_firewall_event_stream(O, Events, PrintedHeader0),
            firewall_watch_loop(O, Cursor1, Limit, PrintedHeader);
        {error, Err} ->
            die_operator(Err)
    end.

emit_firewall_events(_O, []) ->
    ok;
emit_firewall_events(O, Events) ->
    emit_table(O,
               firewall_event_headers(),
               [firewall_event_row(E) || E <- Events]).

emit_firewall_event_stream(_O, [], PrintedHeader) ->
    PrintedHeader;
emit_firewall_event_stream(#{format := json}, Events, PrintedHeader) ->
    [emit_json(to_json(firewall_event, E)) || E <- Events],
    PrintedHeader;
emit_firewall_event_stream(#{format := plain} = O, Events, PrintedHeader) ->
    emit_firewall_events(O, Events),
    PrintedHeader;
emit_firewall_event_stream(O, Events, PrintedHeader) ->
    Headers = firewall_event_headers(),
    Rows = [firewall_event_row(E) || E <- Events],
    emit_table_maybe_header(O, Headers, Rows, not PrintedHeader),
    true.

firewall_event_headers() ->
    [seq, ts, severity, kind, source, table, owner, src_ip, dst_ip, chain, dst_port, reason].

firewall_event_row(E) ->
    [maps:get(seq, E, 0),
     format_ts(maps:get(ts_wall, E, 0)),
     maps:get(severity, E, <<"-">>),
     maps:get(kind, E, <<"-">>),
     maps:get(source, E, <<"-">>),
     maps:get(table, E, <<"-">>),
     maps:get(table_owner, E, <<"-">>),
     format_ip_value(maps:get(src_ip, E, undefined)),
     format_ip_value(maps:get(dst_ip, E, undefined)),
     maps:get(chain, E, <<"-">>),
     maps:get(dst_port, E, <<"-">>),
     maps:get(reason, E, <<"-">>)].

emit_firewall_status(Status) ->
    Events = maps:get(events, Status, #{}),
    Guard = maps:get(guard, Status, #{}),
    emit_table(#{format => table},
               [component, key, value],
               firewall_status_rows(events, Events) ++
               firewall_status_rows(guard, Guard)).

firewall_status_rows(Component, Map) when is_map(Map) ->
    [[Component, K, V] || {K, V} <- lists:sort(maps:to_list(Map))];
firewall_status_rows(Component, Other) ->
    [[Component, status, Other]].


%%====================================================================
%% Distribution + RPC
%%====================================================================

ensure_distribution(#{cookie_file := CookiePath, node := TargetNode}) ->
    case get(ek_distribution_started) of
        {TargetNode, CookiePath} ->
            ok;
        _ ->
            start_distribution(CookiePath, TargetNode)
    end.

start_distribution(CookiePath, TargetNode) ->
    case file:read_file(CookiePath) of
        {ok, CookieBin} ->
            Cookie = list_to_atom(string:trim(binary_to_list(CookieBin))),
            case node() of
                nonode@nohost ->
                    CtlNodeName = list_to_atom(
                        "ek_" ++ os:getpid() ++ "@" ++ short_host()),
                    {ok, _} = net_kernel:start([CtlNodeName, shortnames]);
                _ ->
                    ok
            end,
            true = erlang:set_cookie(node(), Cookie),
            case net_adm:ping(TargetNode) of
                pong ->
                    put(ek_distribution_started, {TargetNode, CookiePath}),
                    ok;
                pang ->
                    die(error, io_lib:format(
                        "can't reach erlkoenig at ~p — is the service running?",
                        [TargetNode]))
            end;
        {error, Reason} ->
            die(error, io_lib:format("can't read cookie ~s: ~p", [CookiePath, Reason]))
    end.

call(O, Module, Function, Args) ->
    case os:getenv("ERLKOENIG_EK_MOCK_RPC") of
        false -> call_rpc(O, Module, Function, Args);
        Path  -> call_mock(Path, Module, Function, Args)
    end.

call_rpc(#{node := Target} = O, Module, Function, Args) ->
    ensure_distribution(O),
    case rpc:call(Target, Module, Function, Args, 30_000) of
        {badrpc, {'EXIT', {undef, Stack}}} ->
            die(error, format_undef_diagnosis(Module, Function, Args,
                                              Target, Stack));
        {badrpc, nodedown} ->
            die(error, io_lib:format("node ~p is down", [Target]));
        {badrpc, {'EXIT', {timeout, _}}} ->
            die(error, io_lib:format("timeout calling ~p:~p on ~p",
                                     [Module, Function, Target]));
        {badrpc, Reason} ->
            die(error, io_lib:format("RPC ~p:~p failed: ~p",
                                     [Module, Function, Reason]));
        Result ->
            Result
    end.

call_mock(Path, Module, Function, Args) ->
    {ok, [State0]} = file:consult(Path),
    Calls = maps:get(calls, State0, []),
    State = State0#{calls => Calls ++ [{Module, Function, Args}]},
    ok = file:write_file(Path, io_lib:format("~p.~n", [State])),
    Responses = maps:get(responses, State, #{}),
    case maps:find({Module, Function}, Responses) of
        {ok, Reply} -> Reply;
        error -> die(error, io_lib:format(
            "rpc mock missing response for ~p:~p", [Module, Function]))
    end.

op_call(O, Function, Args) ->
    case os:getenv("ERLKOENIG_EK_MOCK_OPERATOR_API") of
        false -> op_call_rpc(O, Function, Args);
        Path  -> op_call_mock(Path, Function, Args)
    end.

op_call_rpc(#{node := Target} = O, Function, Args) ->
    ensure_distribution(O),
    case rpc:call(Target, erlkoenig_operator_api, Function, Args, 30_000) of
        {badrpc, {'EXIT', {undef, Stack}}} ->
            die(error, format_undef_diagnosis(erlkoenig_operator_api,
                                              Function, Args, Target,
                                              Stack));
        {badrpc, nodedown} ->
            die(error, io_lib:format("node ~p is down", [Target]));
        {badrpc, {'EXIT', {timeout, _}}} ->
            die(error, io_lib:format("timeout calling erlkoenig_operator_api:~p on ~p",
                                     [Function, Target]));
        {badrpc, Reason} ->
            die(error, io_lib:format("RPC erlkoenig_operator_api:~p failed: ~p",
                                     [Function, Reason]));
        Result ->
            Result
    end.

%% Distinguish "the wrapper itself is missing on the remote" from "an
%% inner call inside the wrapper is missing". The previous code matched
%% any `{undef, _}' in the badrpc and always blamed the outer wrapper —
%% which silently mis-attributed runtime-dep undef errors (e.g. an
%% OTP function not present on the remote) to a stale CLI. The first
%% frame of the undef stack is the actual undefined call.
format_undef_diagnosis(Module, Function, OuterArgs, Target, Stack) ->
    OuterArity = length(OuterArgs),
    case Stack of
        [{Module, Function, InnerArgs, _Loc} | _]
          when length(InnerArgs) =:= OuterArity ->
            io_lib:format(
              "remote call ~p:~p/~p is undef on ~p — "
              "release may be older than this CLI",
              [Module, Function, OuterArity, Target]);
        [{Module, Function, InnerArity, _Loc} | _]
          when InnerArity =:= OuterArity ->
            io_lib:format(
              "remote call ~p:~p/~p is undef on ~p — "
              "release may be older than this CLI",
              [Module, Function, OuterArity, Target]);
        [{InnerMod, InnerFun, InnerArgs, _Loc} | _] when is_list(InnerArgs) ->
            io_lib:format(
              "remote call ~p:~p/~p crashed on ~p: "
              "internal call ~p:~p/~p is undef "
              "(likely OTP version skew or missing runtime dependency)",
              [Module, Function, OuterArity, Target,
               InnerMod, InnerFun, length(InnerArgs)]);
        [{InnerMod, InnerFun, InnerArity, _Loc} | _] when is_integer(InnerArity) ->
            io_lib:format(
              "remote call ~p:~p/~p crashed on ~p: "
              "internal call ~p:~p/~p is undef "
              "(likely OTP version skew or missing runtime dependency)",
              [Module, Function, OuterArity, Target,
               InnerMod, InnerFun, InnerArity]);
        _ ->
            io_lib:format(
              "remote call ~p:~p/~p is undef on ~p — "
              "release may be older than this CLI (no detail in stack)",
              [Module, Function, OuterArity, Target])
    end.

op_call_mock(Path, Function, Args) ->
    {ok, [State0]} = file:consult(Path),
    Calls = maps:get(calls, State0, []),
    State = State0#{calls => Calls ++ [{Function, Args}]},
    ok = file:write_file(Path, io_lib:format("~p.~n", [State])),
    Responses = maps:get(responses, State, #{}),
    maps:get(Function, Responses,
             {error, #{code => 'EK_OPERATOR_INTERNAL',
                       data => #{op => Function, raw => mock_missing_response}}}).

operator_value(O, Function, Args) ->
    case op_call(O, Function, Args) of
        {ok, Value} -> Value;
        {error, Err} -> die_operator(Err)
    end.

die_operator(#{code := 'EK_OPERATOR_NOT_FOUND'} = Err) ->
    die(not_found, operator_error_message(Err));
die_operator(#{code := 'EK_OPERATOR_BAD_ARGUMENT'} = Err) ->
    die(usage, operator_error_message(Err));
die_operator(Err) ->
    die(error, operator_error_message(Err)).

operator_error_message(#{code := Code, data := Data}) ->
    case Code of
        'EK_OPERATOR_NOT_FOUND' ->
            io_lib:format("~s '~s' not found",
                          [to_value(maps:get(resource, Data, resource)),
                           to_value(maps:get(key, Data, ""))]);
        'EK_OPERATOR_BAD_ARGUMENT' ->
            io_lib:format("bad argument ~s: expected ~s",
                          [to_value(maps:get(argument, Data, argument)),
                           to_value(maps:get(expected, Data, ""))]);
        _ ->
            io_lib:format("~s: ~p", [to_value(Code), Data])
    end;
operator_error_message(Other) ->
    io_lib:format("~p", [Other]).

short_host() ->
    {ok, Host} = inet:gethostname(),
    Host.

default_target_node() ->
    {ok, Host} = inet:gethostname(),
    list_to_atom("erlkoenig@" ++ Host).

default_cookie_file() ->
    case os:getenv("ERLKOENIG_COOKIE_FILE") of
        false ->
            Candidates = ["/etc/erlkoenig/cookie",
                          user_cookie_file()],
            case lists:filter(fun filelib:is_regular/1, Candidates) of
                [P | _] -> P;
                []      -> hd(Candidates)  %% best guess for error msg
            end;
        Path -> Path
    end.

user_cookie_file() ->
    case os:getenv("HOME") of
        false -> filename:join([".", ".config", "erlkoenig", "cookie"]);
        Home  -> filename:join([Home, ".config", "erlkoenig", "cookie"])
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
parse_global_opts(["--all" | Rest], Acc) ->
    parse_global_opts(Rest, Acc#{all => true});
parse_global_opts(["--yes" | Rest], Acc) ->
    parse_global_opts(Rest, Acc#{yes => true});
parse_global_opts(["--dry-run" | Rest], Acc) ->
    parse_global_opts(Rest, Acc#{dry_run => true});
parse_global_opts(["--allow-lockout" | Rest], Acc) ->
    parse_global_opts(Rest, Acc#{allow_lockout => true});
parse_global_opts(["--limit", Limit | Rest], Acc) ->
    parse_global_opts(Rest, Acc#{limit => parse_positive_int("--limit", Limit)});
parse_global_opts([Arg | Rest], Acc) when is_list(Arg) ->
    %% Also accept --key=value form for shell-friendly invocations.
    case string:split(Arg, "=") of
        ["--node", V]        -> parse_global_opts(Rest, Acc#{node => list_to_atom(V)});
        ["--cookie-file", V] -> parse_global_opts(Rest, Acc#{cookie_file => V});
        ["--format", V]      -> parse_global_opts(Rest, Acc#{format => list_to_atom(V)});
        ["--all"]            -> parse_global_opts(Rest, Acc#{all => true});
        ["--yes"]            -> parse_global_opts(Rest, Acc#{yes => true});
        ["--dry-run"]        -> parse_global_opts(Rest, Acc#{dry_run => true});
        ["--allow-lockout"]  -> parse_global_opts(Rest, Acc#{allow_lockout => true});
        ["--limit", V]       -> parse_global_opts(Rest, Acc#{limit => parse_positive_int("--limit", V)});
        _                    ->
            {NextAcc, NextRest} = parse_global_opts(Rest, Acc),
            {NextAcc, [Arg | NextRest]}
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
    emit_table_maybe_header(#{format => table}, Headers, Rows, true).

emit_table_maybe_header(#{format := json} = O, Headers, Rows, _PrintHeader) ->
    emit_table(O, Headers, Rows);
emit_table_maybe_header(#{format := plain} = O, Headers, Rows, _PrintHeader) ->
    emit_table(O, Headers, Rows);
emit_table_maybe_header(_, Headers, Rows, PrintHeader) ->
    HeaderStrs = [atom_to_list(H) || H <- Headers],
    StringRows = [[to_value(V) || V <- Row] || Row <- Rows],
    Widths = column_widths([HeaderStrs | StringRows]),
    case PrintHeader of
        true ->
            print_row(HeaderStrs, Widths),
            print_row([lists:duplicate(W, $-) || W <- Widths], Widths);
        false ->
            ok
    end,
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

to_string(V) when is_list(V) ->
    case io_lib:char_list(V) of
        true  -> V;
        false -> lists:flatten(io_lib:format("~p", [V]))
    end;
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
        true  -> unicode:characters_to_binary(V);
        false -> [to_jsonable(X) || X <- V]
    end;
to_jsonable(V) -> V.

%%====================================================================
%% JSON output contract — see docs/CLI.md "JSON Output Contract".
%%
%% Stable, tool-friendly schema for `ek --format json ...`. Plain/table
%% output is unchanged. Per-command normalizers produce maps with
%% snake_case binary keys and JSON-safe values; a generic fallback
%% handles unknown nested terms and emits a one-shot drift notice on
%% stderr per (Command, Field).
%%====================================================================

%% Single entry point: emit a JSON document on stdout.
emit_json(Term) ->
    io:format("~ts~n", [json:encode(Term)]).

%% Per-command normalizer dispatch. Add a clause here when a new
%% command surfaces structured data via --format json.
to_json(container_summary, Info) -> normalize_container_summary(Info);
to_json(container_info,    Info) -> normalize_container_info(Info);
to_json(net_info,          NI)   -> normalize_net_info(NI);
to_json(timeline_step,     S)    -> normalize_timeline_step(S);
to_json(volume,            V)    -> normalize_volume(V);
to_json(pod,               P)    -> normalize_pod(P);
to_json(quarantine_entry,  E)    -> normalize_quarantine_entry(E);
to_json(admission_snapshot, S)   -> normalize_admission_snapshot(S);
to_json(node_health,       H)    -> normalize_node_health(H);
to_json(nft_counter,       C)    -> normalize_nft_counter(C);
to_json(firewall_status,   S)    -> normalize_firewall_status(S);
to_json(firewall_event,    E)    -> normalize_firewall_event(E).

%% Apply explicit field handlers; unknown fields fall through to
%% to_json_generic and may emit a one-shot notice if the value is a
%% complex term.
apply_known(Kind, Known, Map) when is_map(Map) ->
    maps:fold(fun(K, V, Acc) ->
        case maps:find(K, Known) of
            {ok, Fn} -> Acc#{normalize_key(K) => Fn(V)};
            error    ->
                maybe_notice(Kind, K, V),
                Acc#{normalize_key(K) => to_json_generic(V)}
        end
    end, #{}, Map).

%% Generic recursive normalizer. Handles atom, undefined, integer,
%% float, binary, pid, ref, IPv4-shaped tuples, lists (with string
%% detection), and maps. Unknown tuples/non-IP shapes are stringified
%% as a last resort; per-kind callers should detect that case via
%% maybe_notice before dispatching here.
to_json_generic(undefined) -> null;
to_json_generic(null)      -> null;
to_json_generic(true)      -> true;
to_json_generic(false)     -> false;
to_json_generic(I) when is_integer(I) -> I;
to_json_generic(F) when is_float(F)   -> F;
to_json_generic(A) when is_atom(A)    -> atom_to_binary(A, utf8);
to_json_generic(P) when is_pid(P)        -> iolist_to_binary(pid_to_list(P));
to_json_generic(R) when is_reference(R)  -> iolist_to_binary(ref_to_list(R));
to_json_generic({A,B,C,D}) when is_integer(A), A >= 0, A =< 255,
                                is_integer(B), B >= 0, B =< 255,
                                is_integer(C), C >= 0, C =< 255,
                                is_integer(D), D >= 0, D =< 255 ->
    ip_to_binary({A,B,C,D});
to_json_generic({_,_,_,_,_,_,_,_} = T) ->
    case is_ipv6_tuple(T) of
        true  -> ip_to_binary(T);
        false -> tuple_to_string(T)
    end;
to_json_generic(B) when is_binary(B) ->
    binary_to_string_or_hex(B);
to_json_generic(L) when is_list(L) ->
    case io_lib:char_list(L) of
        true  -> unicode:characters_to_binary(L);
        false -> [to_json_generic(X) || X <- L]
    end;
to_json_generic(M) when is_map(M) ->
    maps:fold(fun(K, V, Acc) ->
        Acc#{normalize_key(K) => to_json_generic(V)}
    end, #{}, M);
to_json_generic(T) when is_tuple(T) -> tuple_to_string(T).

%% Map keys are binary snake_case strings. Atom keys lose the atom
%% identity in JSON; binary keys are passed through (assumed already
%% snake_case from the wrapper layer).
normalize_key(K) when is_atom(K)   -> atom_to_binary(K, utf8);
normalize_key(K) when is_binary(K) -> K;
normalize_key(K)                   -> iolist_to_binary(io_lib:format("~p", [K])).

%% Drift notice — at most once per (Command, Kind) per CLI invocation.
%% Triggered only by complex fallback values (tuples that aren't IPs,
%% maps, non-string lists). Simple scalars (atom/binary/int/pid/ref)
%% don't notice — they have stable conversions in to_json_generic.
maybe_notice(_Kind, _Field, V)
  when is_atom(V); is_integer(V); is_float(V); is_pid(V); is_reference(V) ->
    ok;
maybe_notice(_Kind, _Field, V) when is_binary(V) ->
    ok;
maybe_notice(_Kind, _Field, undefined) ->
    ok;
maybe_notice(Kind, Field, _V) ->
    Key = {ek_json_notice, Kind, Field},
    case get(Key) of
        undefined ->
            put(Key, true),
            io:format(standard_error,
                      "notice: ek --format json fell back to generic "
                      "normalizer for ~p.~p; consider an explicit handler~n",
                      [Kind, Field]);
        _ -> ok
    end.

%% IPv4/IPv6 tuple → printable form. Uses inet:ntoa for IPv6 to get
%% RFC-5952 compressed form ("fe80::1" not "fe80:0:0:0:0:0:0:1").
ip_to_binary(undefined) -> null;
ip_to_binary(<<A,B,C,D>>) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A,B,C,D]));
ip_to_binary(<<A:16/big, B:16/big, C:16/big, D:16/big,
               E:16/big, F:16/big, G:16/big, H:16/big>>) ->
    iolist_to_binary(inet:ntoa({A,B,C,D,E,F,G,H}));
ip_to_binary({A,B,C,D}) when is_integer(A), is_integer(B),
                             is_integer(C), is_integer(D) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A,B,C,D]));
ip_to_binary({_,_,_,_,_,_,_,_} = T) ->
    iolist_to_binary(inet:ntoa(T));
ip_to_binary(B) when is_binary(B) -> B.

is_ipv6_tuple({A,B,C,D,E,F,G,H}) ->
    lists:all(fun(X) -> is_integer(X) andalso X >= 0 andalso X =< 65535 end,
              [A,B,C,D,E,F,G,H]).

%% Unix-ms → ISO-8601 UTC with millisecond precision.
ts_ms_to_iso(Ms) when is_integer(Ms) ->
    Sec = Ms div 1000,
    Frac = Ms rem 1000,
    {{Y, Mo, D}, {H, Mi, S}} = calendar:system_time_to_universal_time(Sec, second),
    iolist_to_binary(io_lib:format(
        "~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.~3..0BZ",
        [Y, Mo, D, H, Mi, S, Frac])).

%% Binary → UTF-8 string, or lowercase hex if not valid UTF-8.
binary_to_string_or_hex(B) when is_binary(B) ->
    case unicode:characters_to_binary(B, utf8, utf8) of
        Bin when is_binary(Bin) -> Bin;
        _ -> binary:encode_hex(B, lowercase)
    end.

tuple_to_string(T) ->
    iolist_to_binary(io_lib:format("~p", [T])).

%% Per-kind normalizers
%% --------------------

normalize_container_summary(Info) ->
    Net = maps:get(net_info, Info, #{}),
    #{
        <<"name">>          => to_str_or_null(
                                   maps:get(name, Info,
                                            maps:get(id, Info, undefined))),
        <<"state">>         => atom_to_str_or_null(maps:get(state, Info, undefined)),
        <<"ip">>            => ip_to_binary(maps:get(ip, Net, undefined)),
        <<"zone">>          => to_str_or_null(maps:get(zone, Info, undefined)),
        <<"restart_count">> => maps:get(restart_count, Info, 0)
    }.

normalize_container_info(Info0) ->
    %% ct inspect: keep all observed fields, normalize each, plus the
    %% synthesized timeline. Unknown fields go through generic with
    %% drift-notice on first complex term.
    Known = #{
        id            => fun to_str_or_null/1,
        name          => fun to_str_or_null/1,
        binary        => fun to_str_or_null/1,
        zone          => fun to_str_or_null/1,
        state         => fun atom_to_str_or_null/1,
        seccomp       => fun atom_to_str_or_null/1,
        restart       => fun atom_to_str_or_null/1,
        os_pid        => fun int_or_null/1,
        restart_count => fun int_or_null/1,
        netns_path    => fun to_str_or_null/1,
        socket_path   => fun to_str_or_null/1,
        handshake     => fun to_json_generic/1,
        args          => fun list_of_str/1,
        ports         => fun list_of_str/1,
        caps          => fun list_of_str/1,
        volumes       => fun(L) when is_list(L) ->
                              [normalize_container_volume(V) || V <- L];
                             (_) -> []
                          end,
        net_info      => fun(V) -> case is_map(V) of
                                       true  -> normalize_net_info(V);
                                       false -> null
                                   end
                          end,
        stats         => fun(V) -> case is_map(V) of
                                       true  -> to_json_generic(V);
                                       false -> null
                                   end
                          end,
        limits        => fun(V) -> case is_map(V) of
                                       true  -> to_json_generic(V);
                                       false -> null
                                   end
                          end,
        exit_info     => fun(V) -> case is_map(V) of
                                       true  -> to_json_generic(V);
                                       false -> null
                                   end
                          end,
        error         => fun to_json_generic/1,
        runtime_timeline => fun(L) when is_list(L) ->
                                  [to_json_generic(S) || S <- L];
                                 (_) -> []
                              end,
        timeline      => fun(L) -> [normalize_timeline_step(S) || S <- L] end
    },
    apply_known(container_info, Known, Info0).

normalize_net_info(NI) ->
    Known = #{
        ip             => fun ip_to_binary/1,
        gateway        => fun ip_to_binary/1,
        netmask        => fun int_or_null/1,
        zone           => fun to_str_or_null/1,
        iface          => fun to_str_or_null/1,
        container_veth => fun to_str_or_null/1,
        host_veth      => fun to_str_or_null/1,
        attach         => fun normalize_net_attach/1
    },
    apply_known(net_info, Known, NI).

normalize_net_attach(M) when is_map(M) ->
    Known = #{
        mode   => fun atom_to_str_or_null/1,
        os_pid => fun int_or_null/1,
        slave  => fun to_str_or_null/1
    },
    apply_known(net_info_attach, Known, M);
normalize_net_attach(_) -> null.

normalize_timeline_step(#{step := Step, status := Status}) ->
    #{<<"step">>   => atom_to_str_or_null(Step),
      <<"status">> => atom_to_str_or_null(Status)}.

normalize_volume(Vol) ->
    Map = #{
        <<"uuid">>        => to_str_or_null(maps:get(uuid, Vol, undefined)),
        <<"container">>   => to_str_or_null(maps:get(container, Vol, undefined)),
        <<"persist">>     => to_str_or_null(maps:get(persist, Vol, undefined)),
        <<"host_path">>   => to_str_or_null(maps:get(host_path, Vol, undefined)),
        <<"lifecycle">>   => atom_to_str_or_null(maps:get(lifecycle, Vol, undefined)),
        <<"quota_bytes">> => int_or_null(maps:get(quota_bytes, Vol, undefined))
    },
    Map.

normalize_container_volume(Vol) when is_map(Vol) ->
    #{
        <<"uuid">>      => to_str_or_null(maps:get(uuid, Vol, undefined)),
        <<"container">> => to_str_or_null(maps:get(container, Vol, undefined)),
        <<"persist">>   => to_str_or_null(maps:get(persist, Vol, undefined)),
        <<"host">>      => to_str_or_null(maps:get(host, Vol, undefined)),
        <<"read_only">> => bool_or_null(maps:get(read_only, Vol, undefined)),
        <<"lifecycle">> => atom_to_str_or_null(maps:get(lifecycle, Vol, undefined)),
        <<"opts">>      => to_str_or_null(maps:get(opts, Vol, undefined))
    };
normalize_container_volume(Vol) ->
    to_json_generic(Vol).

normalize_pod(P) ->
    #{
        <<"name">>     => to_str_or_null(maps:get(name, P, undefined)),
        <<"pid">>      => pid_to_str_or_null(maps:get(pid, P, undefined)),
        <<"children">> => int_or_null(maps:get(children, P, undefined))
    }.

normalize_quarantine_entry(E) ->
    SinceMs = maps:get(since, E, undefined),
    #{
        <<"hash">>     => to_str_or_null(maps:get(hash, E, undefined)),
        <<"reason">>   => normalize_quarantine_reason(maps:get(reason, E, undefined)),
        <<"since">>    => case is_integer(SinceMs) of
                              true  -> ts_ms_to_iso(SinceMs);
                              false -> null
                          end,
        <<"since_ms">> => int_or_null(SinceMs)
    }.

normalize_quarantine_reason(undefined) -> null;
normalize_quarantine_reason(A) when is_atom(A)   -> atom_to_binary(A, utf8);
normalize_quarantine_reason(B) when is_binary(B) -> B;
normalize_quarantine_reason({crashloop, Count, WindowMs})
  when is_integer(Count), is_integer(WindowMs) ->
    #{<<"kind">> => <<"crashloop">>,
      <<"count">> => Count,
      <<"window_ms">> => WindowMs};
normalize_quarantine_reason(Other) ->
    maybe_notice(quarantine_entry, reason, Other),
    tuple_to_string(Other).

normalize_admission_snapshot(S) ->
    Zones = maps:get(zone_in_flight, S, #{}),
    ZonesJson = case is_map(Zones) of
        true  -> maps:fold(fun(K, V, Acc) ->
                     Acc#{normalize_key(K) => int_or_null(V)}
                 end, #{}, Zones);
        false -> #{}
    end,
    #{
        <<"host_in_flight">> => int_or_null(maps:get(host_in_flight, S, undefined)),
        <<"zone_in_flight">> => ZonesJson,
        <<"queued">>         => int_or_null(maps:get(queued, S, undefined))
    }.

normalize_node_health(H) ->
    #{
        <<"uptime_ms">>    => int_or_null(maps:get(uptime_ms, H, undefined)),
        <<"sup_children">> => int_or_null(maps:get(sup_children, H, undefined))
    }.

normalize_nft_counter(C) ->
    #{
        <<"table">>         => to_str_or_null(maps:get(table, C, undefined)),
        <<"name">>          => to_str_or_null(maps:get(name, C, undefined)),
        <<"packets">>       => number_or_null(maps:get(packets, C, undefined)),
        <<"bytes">>         => number_or_null(maps:get(bytes, C, undefined)),
        <<"total_packets">> => number_or_null(
                                  maps:get(total_packets, C,
                                           maps:get(packets, C, undefined))),
        <<"total_bytes">>   => number_or_null(
                                  maps:get(total_bytes, C,
                                           maps:get(bytes, C, undefined))),
        <<"pps">>           => number_or_null(maps:get(pps, C, undefined)),
        <<"bps">>           => number_or_null(maps:get(bps, C, undefined)),
        <<"interval">>      => int_or_null(maps:get(interval, C, undefined))
    }.

normalize_firewall_status(S) ->
    #{
        <<"events">> => to_json_generic(maps:get(events, S, #{})),
        <<"guard">>  => to_json_generic(maps:get(guard, S, #{}))
    }.

normalize_firewall_event(E) ->
    Known = #{
        seq         => fun int_or_null/1,
        id          => fun to_str_or_null/1,
        ts_mono     => fun int_or_null/1,
        ts_wall     => fun int_or_null/1,
        source      => fun atom_to_str_or_null/1,
        severity    => fun atom_to_str_or_null/1,
        kind        => fun atom_to_str_or_null/1,
        table       => fun to_str_or_null/1,
        table_owner => fun atom_to_str_or_null/1,
        chain       => fun to_str_or_null/1,
        counter     => fun to_str_or_null/1,
        src_ip      => fun ip_to_binary/1,
        dst_ip      => fun ip_to_binary/1,
        proto       => fun atom_to_str_or_null/1,
        src_port    => fun int_or_null/1,
        dst_port    => fun int_or_null/1,
        verdict     => fun atom_to_str_or_null/1,
        reason      => fun atom_to_str_or_null/1,
        evidence    => fun normalize_firewall_evidence/1,
        labels      => fun list_of_str/1
    },
    apply_known(firewall_event, Known, E).

normalize_firewall_evidence(undefined) -> #{};
normalize_firewall_evidence(M) when is_map(M) ->
    maps:fold(fun(K, V, Acc) ->
        Acc#{normalize_key(K) => normalize_firewall_evidence_value(K, V)}
    end, #{}, M);
normalize_firewall_evidence(L) when is_list(L) ->
    [normalize_firewall_evidence(V) || V <- L];
normalize_firewall_evidence(Other) ->
    to_json_generic(Other).

normalize_firewall_evidence_value(K, V)
  when K =:= src_raw; K =:= dst_raw;
       K =:= <<"src_raw">>; K =:= <<"dst_raw">> ->
    ip_to_binary(V);
normalize_firewall_evidence_value(_K, V) ->
    normalize_firewall_evidence(V).

%% Small leaf converters — keep them honest about absence vs zero.
to_str_or_null(undefined) -> null;
to_str_or_null(null)      -> null;
to_str_or_null(B) when is_binary(B) -> binary_to_string_or_hex(B);
to_str_or_null(A) when is_atom(A)   -> atom_to_binary(A, utf8);
to_str_or_null(L) when is_list(L)   ->
    case io_lib:char_list(L) of
        true  -> unicode:characters_to_binary(L);
        false -> tuple_to_string(list_to_tuple(L))
    end;
to_str_or_null(I) when is_integer(I) -> integer_to_binary(I);
to_str_or_null(Other) -> tuple_to_string(Other).

atom_to_str_or_null(undefined) -> null;
atom_to_str_or_null(null)      -> null;
atom_to_str_or_null(A) when is_atom(A) -> atom_to_binary(A, utf8);
atom_to_str_or_null(B) when is_binary(B) -> B;
atom_to_str_or_null(Other) -> tuple_to_string(Other).

int_or_null(undefined) -> null;
int_or_null(I) when is_integer(I) -> I;
int_or_null(_) -> null.

bool_or_null(undefined) -> null;
bool_or_null(true) -> true;
bool_or_null(false) -> false;
bool_or_null(_) -> null.

number_or_null(undefined) -> null;
number_or_null(I) when is_integer(I) -> I;
number_or_null(F) when is_float(F) -> F;
number_or_null(_) -> null.

pid_to_str_or_null(undefined) -> null;
pid_to_str_or_null(P) when is_pid(P) -> iolist_to_binary(pid_to_list(P));
pid_to_str_or_null(B) when is_binary(B) -> B;
pid_to_str_or_null(_) -> null.

list_of_str(undefined) -> [];
list_of_str(L) when is_list(L) ->
    [to_str_or_null(X) || X <- L];
list_of_str(_) -> [].
%%==================================================================== END JSON

format_ip(undefined) -> "-";
format_ip({A, B, C, D}) ->
    io_lib:format("~B.~B.~B.~B", [A, B, C, D]).

format_ip_value(undefined) -> <<"-">>;
format_ip_value(<<A, B, C, D>>) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A, B, C, D]));
format_ip_value(<<A:16/big, B:16/big, C:16/big, D:16/big,
                  E:16/big, F:16/big, G:16/big, H:16/big>>) ->
    iolist_to_binary(inet:ntoa({A, B, C, D, E, F, G, H}));
format_ip_value({A, B, C, D}) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A, B, C, D]));
format_ip_value({_,_,_,_,_,_,_,_} = T) ->
    iolist_to_binary(inet:ntoa(T));
format_ip_value(B) when is_binary(B) -> B;
format_ip_value(Other) -> io_lib:format("~p", [Other]).

format_ts(Ms) when is_integer(Ms) ->
    Sec = Ms div 1000,
    {{Y, Mo, D}, {H, Mi, S}} = calendar:system_time_to_universal_time(Sec, second),
    io_lib:format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ",
                  [Y, Mo, D, H, Mi, S]);
format_ts(Other) -> io_lib:format("~p", [Other]).

format_term(T) when is_atom(T) -> atom_to_list(T);
format_term(T)                 -> lists:flatten(io_lib:format("~p", [T])).

normalize_hash(Str) when is_list(Str) ->
    normalize_hash(list_to_binary(Str));
normalize_hash(Bin) when is_binary(Bin) ->
    Lower = list_to_binary(string:lowercase(binary_to_list(Bin))),
    try binary:decode_hex(Lower) of
        Raw when byte_size(Raw) =:= 32 -> Lower;
        _ -> die(usage, "quarantine hash must be 64 hex chars (SHA-256)")
    catch _:_ -> die(usage, "quarantine hash must be hex-encoded")
    end.

parse_positive_int(Name, Value) ->
    try list_to_integer(Value) of
        I when I > 0 -> I;
        _ -> die(usage, io_lib:format("~s must be a positive integer", [Name]))
    catch
        _:_ -> die(usage, io_lib:format("~s must be a positive integer", [Name]))
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
        "  --cookie-file <path> Cookie file (default: ERLKOENIG_COOKIE_FILE, /etc/erlkoenig/cookie, ~~/.config/erlkoenig/cookie)~n"
        "  --format <fmt>       Output format: table | json | plain (default: table)~n"
        "  --allow-lockout      Bypass host-firewall preflight on `up' / `config load' (you must have out-of-band recovery available)~n"
        "  --limit <n>          Limit rows for commands that return event/history buffers~n"
        "  --version, -V        Print CLI version and exit~n"
        "~n"
        "Areas and commands:~n"
        "  node ping            Liveness check~n"
        "  node version         App version~n"
        "  node health          Uptime + supervisor child count~n"
        "~n"
        "  doctor               Local host and install diagnostics~n"
        "  explain <code>       Explain a structured erlkoenig error code~n"
        "  explain --list       List known structured error codes~n"
        "  explain --component <name>  List known codes for one component~n"
        "~n"
        "  up <file>            Start a stack (accepts .exs or .term)~n"
        "  down <file>          Stop containers declared in <file>~n"
        "  down --all           Stop every running container~n"
        "~n"
        "  ps                   Alias for `ct list`~n"
        "  ct list              All running containers~n"
        "  ct inspect <name>    Full state of one container~n"
        "  ct stop <name>       Send stop signal to one container~n"
        "~n"
        "  pod list [--all]     Active pod supervisors (or all with --all)~n"
        "~n"
        "  config validate <file.term>          Parse + validate a term file~n"
        "  config load     <file.term>          Low-level: same as `up` but no .exs~n"
        "  config reload   <file.term>          Low-level: apply delta against live state~n"
        "~n"
        "  dsl compile <file.exs> [-o <file>]   Compile DSL to .term (uses bundled Elixir)~n"
        "~n"
        "  vol list [--container <name>]      Volumes (optionally filtered)~n"
        "  vol inspect <uuid|persist-name>    Volume metadata~n"
        "  vol destroy <uuid> --yes           Remove metadata + on-disk dir~n"
        "  vol orphans                        UUID dirs without metadata~n"
        "  vol set-quota <uuid> <size>        Set XFS project quota (e.g. 1G)~n"
        "~n"
        "  quarantine list                    Currently quarantined hashes~n"
        "  quarantine add <hash> [--reason X] Manually quarantine~n"
        "  quarantine remove <hash>           Lift a quarantine~n"
        "~n"
        "  admission snapshot                 Spawn-gate state~n"
        "~n"
        "  nft counters                       Live nft counter rates~n"
        "  firewall status                    Event-buffer and guard status~n"
        "  firewall events [--limit N]        Recent canonical firewall events~n"
        "  firewall watch  [--limit N]        Follow canonical firewall events live~n"
        "~n"
        "Examples:~n"
        "  ek up my_stack.exs~n"
        "  ek ps~n"
        "  ek down my_stack.term~n"
        "  ek --format json vol list~n"
        "  ek quarantine add deadbeef00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff --reason operator_ban~n"
        ).

die(Class, Msg) ->
    io:format(standard_error, "error: ~ts~n", [Msg]),
    halt(exit_status(Class)).

exit_status(ok) -> 0;
exit_status(error) -> 1;
exit_status(usage) -> 2;
exit_status(not_found) -> 3.
