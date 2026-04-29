%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(erlkoenig_config).
-moduledoc """
Load and apply Erlkoenig DSL configuration files.

Reads .term files produced by the Elixir DSL (`mix erlkoenig.compile`)
and spawns/configures containers accordingly.

Usage:
  {ok, Pids} = erlkoenig_config:load("/etc/erlkoenig/cluster.term").
  erlkoenig_config:validate("/etc/erlkoenig/cluster.term").
  {ok, Pids} = erlkoenig_config:reload("/etc/erlkoenig/cluster.term").
""".

-export([load/1, load/2, validate/1, reload/1, parse/1, flatten_containers/1,
         declared_names/1]).

-include("erlkoenig_error.hrl").

%% nft compilation and host-table apply live in erlkoenig_config_nft.
%% Call that module directly (apply_nft_tables/5 from ops escripts,
%% resolve_host_refs/expand_nft_rule/find_all_replica_ips/
%% parse_container_name from tests + fuzzing).

%% ETS table for tracking loaded configs
-define(CONFIG_TAB, erlkoenig_config_state).

%%====================================================================
%% Public API
%%====================================================================

-doc "Parse a term file without applying it.".
-spec parse(file:filename()) -> {ok, map()} | {error, term()}.
parse(TermFile) ->
    case file:consult(TermFile) of
        {ok, [Config]} when is_map(Config) ->
            {ok, Config};
        {ok, [Config]} when is_list(Config) ->
            {ok, maps:from_list(Config)};
        {ok, _} ->
            config_error(parse_failed, TermFile, invalid_format),
            {error, {invalid_format, TermFile}};
        {error, Reason} ->
            config_error(parse_failed, TermFile, Reason),
            {error, {read_failed, TermFile, Reason}}
    end.

-doc "Validate a config file (parse + check required fields).".
-spec validate(file:filename()) -> ok | {error, term()}.
validate(TermFile) ->
    case parse(TermFile) of
        {ok, Config} ->
            case erlkoenig_config_validate:validate_config(Config) of
                ok ->
                    ok;
                {error, Reason} = Err ->
                    config_error(validate_failed, TermFile, Reason),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

-doc """
Load a config file. Idempotent: reconciles running state against config.
- Containers in config but not running → start
- Containers running but not in config → stop
- Containers in both → keep (unless config changed)
Can be called multiple times with the same or different files.
""".
-spec load(file:filename()) -> {ok, [{binary(), pid()}]} | {error, term()}.
load(TermFile) ->
    load(TermFile, #{}).

-doc """
Load with explicit options. Currently supported:

  `allow_lockout => boolean()` — if `true`, the host-firewall preflight
  warning is logged but does not abort the load. Default `false`. The
  operator must pass this explicitly via `ek up --allow-lockout` or
  `ek config load --allow-lockout` after reading the warning.
""".
-spec load(file:filename(), map()) ->
    {ok, [{binary(), pid()}]} | {error, term()}.
load(TermFile, Opts) when is_map(Opts) ->
    maybe
        {ok, Config} ?= parse(TermFile),
        ok ?= erlkoenig_config_validate:validate_config(Config),
        ok ?= host_fw_preflight(TermFile, Config, Opts),
        OldConfig = get_stored_config(TermFile),
        Result = apply_config_with_reconciliation(OldConfig, Config),
        store_config(TermFile, Config),
        erlkoenig_events:notify({config_loaded, TermFile, Config}),
        Result
    else
        {error, Reason} = Err ->
            erlkoenig_events:notify({config_failed, TermFile, Err}),
            erlkoenig_error:emit(
              ?EK_ERROR(config, config_load_failed,
                        "erlkoenig_config:load rejected term file",
                        #{path => unicode:characters_to_binary(TermFile),
                          reason => Reason})),
            Err
    end.

%% Host-firewall lockout preflight. Runs after validate_config and
%% before apply. Emits a structured EK_HOST_FW_LOCKOUT_RISK error and
%% aborts the load when the stack would block the operator's SSH
%% reconnect path; honored only if the caller did not pass
%% `allow_lockout => true'.
host_fw_preflight(TermFile, Config, Opts) ->
    case erlkoenig_host_fw_preflight:analyze(Config) of
        {ok, no_concern} ->
            ok;
        {abort, Findings} ->
            case maps:get(allow_lockout, Opts, false) of
                true ->
                    erlkoenig_events:notify(
                      {host_fw_preflight_overridden, TermFile, Findings}),
                    ok;
                _ ->
                    erlkoenig_error:emit(
                      ?EK_ERROR(config, host_fw_lockout_risk,
                                "host firewall stack would lock out the operator",
                                #{path     => unicode:characters_to_binary(TermFile),
                                  findings => Findings,
                                  override => "ek up --allow-lockout"})),
                    {error, {host_fw_lockout_risk, Findings}}
            end
    end.

-doc "Reload a config file. Alias for load/1 (both are idempotent).".
-spec reload(file:filename()) -> {ok, [{binary(), pid()}]} | {error, term()}.
reload(TermFile) ->
    load(TermFile).

-doc """
Return the list of container names declared in a term file, without
applying it. Used by `ek down <file>` to know what to stop.
""".
-spec declared_names(file:filename()) -> {ok, [binary()]} | {error, term()}.
declared_names(TermFile) ->
    case parse(TermFile) of
        {ok, Config} ->
            Names = [iolist_to_binary(maps:get(name, C))
                     || C <- flatten_containers(Config)],
            {ok, Names};
        {error, _} = E ->
            E
    end.

config_error(parse_failed, TermFile, Reason) ->
    erlkoenig_error:emit(
      ?EK_ERROR(config, parse_failed,
                "configuration parse failed",
                #{path => path_binary(TermFile),
                  reason => Reason}));
config_error(validate_failed, TermFile, Reason) ->
    erlkoenig_error:emit(
      ?EK_ERROR(config, validate_failed,
                "configuration validation failed",
                #{path => path_binary(TermFile),
                  reason => Reason})).

path_binary(Path) when is_binary(Path) ->
    Path;
path_binary(Path) when is_atom(Path) ->
    atom_to_binary(Path, utf8);
path_binary(Path) ->
    unicode:characters_to_binary(Path).

%% Validation (validate_config/1, validate_zones/1,
%% validate_containers/1) lives in erlkoenig_config_validate.

%%====================================================================
%% Internal -- Apply
%%====================================================================

-spec apply_config_with_reconciliation(map() | undefined, map()) ->
    {ok, [{binary(), pid()}]}.
apply_config_with_reconciliation(OldConfig, Config) ->
    Report = #{},

    %% 1. Validate images
    Images = maps:get(images, Config, #{}),
    Report1 = validate_images(Images, Report),

    %% 2. Stop removed containers FIRST (before zone cleanup).
    %% Three buckets drive reconciliation:
    %%   ToStop   — running, no longer declared
    %%   ToDrift  — still declared but config changed since last apply;
    %%              stop now, the `ToStart' pass will re-spawn with the
    %%              new spec
    %%   ToStart  — declared, not currently running (computed later,
    %%              after the drift stops have settled)
    %%
    %% RunningNames comes from the live process group: the authoritative
    %% source of truth. OldConfig (persistent_term) is only consulted
    %% for per-container field comparison in detect_drifted/2.
    AllContainers = flatten_containers(Config),
    DeclaredNames = [iolist_to_binary(maps:get(name, C)) || C <- AllContainers],
    RunningNames = erlkoenig_config_drift:running_container_names(),
    ToStop = RunningNames -- DeclaredNames,
    lists:foreach(fun(Name) ->
        logger:info("erlkoenig_config: stopping removed container ~s", [Name]),
        stop_by_name(Name),
        %% Name has left the declared set — reset its persistent restart
        %% counter so a later re-introduction starts at zero.
        erlkoenig_ct:forget_restart_count(Name)
    end, ToStop),

    Drifted = erlkoenig_config_drift:detect_drifted(OldConfig, Config),
    StillRunningDrift = [N || N <- Drifted, lists:member(N, RunningNames)],
    lists:foreach(fun(Name) ->
        logger:info("erlkoenig_config: restarting drifted container ~s", [Name]),
        stop_by_name(Name)
    end, StillRunningDrift),

    %% Give containers time to exit and release veths/IPs
    case ToStop ++ StillRunningDrift of
        []  -> ok;
        _   -> timer:sleep(1000)
    end,
    %% Drifted containers now need to re-appear as "missing" from live
    %% state so the spawn loop below picks them up.
    RunningAfterStops = RunningNames -- (ToStop ++ StillRunningDrift),

    %% 3. Reconcile zones: destroy stale zones (bridges), then create new
    Zones = maps:get(zones, Config, []),
    NewZoneNames = [binary_to_atom(iolist_to_binary(maps:get(name, Z)))
                    || Z <- Zones],
    OldZoneNames = try erlkoenig_zone:zones()
                   catch _:_ -> []
                   end,
    StaleZones = [Z || Z <- OldZoneNames, Z =/= default,
                       not lists:member(Z, NewZoneNames)],
    lists:foreach(fun(Z) ->
        logger:info("erlkoenig_config: destroying stale zone ~s", [Z]),
        case erlkoenig_zone:destroy(Z) of
            ok -> ok;
            {error, zone_not_empty} ->
                %% Force: stop remaining containers in this zone, retry
                erlkoenig_config_zone:force_stop_zone_containers(Z),
                timer:sleep(500),
                erlkoenig_zone:destroy(Z);
            {error, Reason} ->
                logger:warning("erlkoenig_config: zone ~s destroy failed: ~p", [Z, Reason])
        end
    end, StaleZones),
    Report2 = erlkoenig_config_zone:ensure_zones(Zones, Report1),

    %% 3b. Rebuild nft table with zone-aware network config (IPVLAN-only, ADR-0020)
    ZoneNftConfigs = [begin
        Net = maps:get(network, Z, #{}),
        #{network => #{mode => ipvlan,
                       parent => maps:get(parent, Net, <<"ek_default">>),
                       subnet => maps:get(subnet, Z, maps:get(subnet, Net, {10,0,0,0})),
                       netmask => maps:get(netmask, Z, maps:get(netmask, Net, 24))},
          policy => allow_outbound}
    end || Z <- Zones],
    case ZoneNftConfigs of
        [] -> ok;
        _ ->
            _ = erlkoenig_ct_firewall:setup_table(ZoneNftConfigs),
            ok
    end,

    %% 3c. Apply zone network policy (old format only — new format deferred to 6b)
    lists:foreach(fun(#{allows := _, bridge := Bridge} = Zone) ->
        BridgeBin = iolist_to_binary(Bridge),
        erlkoenig_ct_firewall:apply_zone_allows(Zone, BridgeBin);
       (_) -> ok
    end, Zones),

    %% 4. Apply host firewall (skipped when nft_tables present — ADR-0015)
    Report3 = case maps:is_key(nft_tables, Config) of
        true -> Report2#{firewall => nft_tables};
        false -> erlkoenig_config_zone:maybe_apply_firewall(Config, Report2)
    end,

    %% 5. Apply guard + watches
    maybe_configure_guard(resolve_guard_key(Config)),
    Watches = maps:get(watches, Config, maps:get(watch, Config, [])),
    WatchList = if is_list(Watches) -> Watches;
                   is_map(Watches) -> [Watches];
                   true -> []
                end,
    lists:foreach(fun start_watch/1, WatchList),

    %% Start new containers (not already running)
    %% Group by pod instance for pod-supervised startup
    ToStart = DeclaredNames -- RunningAfterStops,
    Pods = maps:get(pods, Config, []),
    HasNftTables = maps:is_key(nft_tables, Config),
    %% When nft_tables present, containers don't get auto-generated firewall chains
    NewContainers0 = [Ct || Ct <- AllContainers,
                      lists:member(iolist_to_binary(maps:get(name, Ct)), ToStart)],
    NewContainers = case HasNftTables of
        true -> [Ct#{firewall => skip_firewall} || Ct <- NewContainers0];
        false -> NewContainers0
    end,
    Results = erlkoenig_config_spawn:spawn_pods(NewContainers, Pods),

    %% 6b. Apply zone chains + pod forward chains (after spawn, need IPs)
    %% Wait for containers to reach running state and have IPs assigned.
    %% Poll instead of fixed sleep — returns as soon as all IPs are known.
    IpMap = wait_for_ips(Results, 10_000),

    Pods = maps:get(pods, Config, []),
    NftTables = maps:get(nft_tables, Config, []),

    _ = case NftTables of
        [] ->
            %% Legacy path: zone chains + pod forward chains (old DSL)
            lists:foreach(fun(#{chains := Chains} = Zone) when is_list(Chains), Chains =/= [] ->
                erlkoenig_config_nft:apply_zone_chains(Zone, IpMap);
               (_) -> ok
            end, Zones),
            erlkoenig_config_nft:apply_pod_forward_chains(Pods, Zones, Results);
        _ ->
            %% New path: nft-transparent DSL (ADR-0015)
            %% nft_tables define ALL firewall rules — skip legacy chain generation
            VethMap = erlkoenig_config_nft:build_veth_map(Results),
            erlkoenig_config_nft:apply_nft_tables(NftTables, IpMap, VethMap, Pods, Zones)
    end,

    %% 7. Apply steering
    Report4 = erlkoenig_config_zone:maybe_apply_steering(Config, AllContainers, Report3),

    %% 8. Log report
    Started = length(Results),
    Stopped = length(ToStop),
    Kept = length(DeclaredNames) - Started,
    logger:info("erlkoenig_config: reconciled — ~p started, ~p stopped, ~p kept",
                [Started, Stopped, Kept]),
    erlkoenig_config_zone:log_deploy_report(Report4, Started, length(AllContainers)),

    {ok, Results}.

%% Drift detection (`detect_drifted/2', `containers_by_name/1',
%% `container_differs/2', `running_container_names/0') lives in
%% erlkoenig_config_drift. That module is the Glasbox seam for
%% which fields cause a restart on reload — see `container_differs'
%% for the full list and the historical Muster-3 bug it covers.

%% Flatten containers from pods.
%%
%% New term shape (as of the "one pod, inline zone+replicas" DSL refactor):
%%
%%   pods     = [#{name, strategy, containers: [#{name, binary, zone, replicas, ...}]}]
%%   zones    = [#{name, subnet, netmask, network, pool}]   (no `deployments')
%%
%% Each container inside a pod carries its own `zone` and `replicas`.
%% The flat container list is built by expanding each container N times
%% where N = its replica count.
%%
%% A per-zone IP counter is maintained so that containers sharing a zone
%% across different pods do not collide on IPs.
%% Kept as a thin wrapper so tests, fuzz suites and `ek' tooling
%% keep calling `erlkoenig_config:flatten_containers/1' unchanged.
%% The real implementation, together with `zone_subnet_prefix/1' and
%% `expand_container_replicas/4', lives in erlkoenig_config_flatten.
-spec flatten_containers(map()) -> [map()].
flatten_containers(Config) ->
    erlkoenig_config_flatten:flatten_containers(Config).

%% Validate image paths exist on disk
-spec validate_images(map(), map()) -> map().
validate_images(Images, Report) when is_map(Images) ->
    Results = maps:fold(fun(Name, Path, Acc) ->
        case filelib:is_regular(Path) of
            true ->
                [{Name, ok} | Acc];
            false ->
                logger:warning("erlkoenig_config: image ~s not found at ~s",
                               [Name, Path]),
                [{Name, {not_found, Path}} | Acc]
        end
    end, [], Images),
    Report#{images => maps:from_list(Results)};
validate_images(_, Report) ->
    Report.

%% Zone/firewall/steering apply helpers (ensure_zones/2,
%% maybe_apply_firewall/2, maybe_apply_steering/3,
%% find_container_ip/2, log_deploy_report/3) and the
%% force_stop_zone_containers/1 helper for subnet-change
%% recreations live in erlkoenig_config_zone.

%% Spawn logic (spawn_pods/2, spawn_container/1, build_spawn_opts/1,
%% maybe_add_health_check/2, private `copy_if/3') lives in
%% erlkoenig_config_spawn. `build_spawn_opts' is the Glasbox seam
%% for capability-field propagation — every DSL field the runtime
%% needs at spawn time must be in its `Keys' list.

%%====================================================================
%% Internal -- Guard
%%====================================================================

%% The Elixir DSL emits its guard block under `ct_guard`, older term
%% files used `guard`. Normalize to a single shape before dispatching.
-spec resolve_guard_key(map()) -> map().
resolve_guard_key(Config) ->
    case {maps:find(guard, Config), maps:find(ct_guard, Config)} of
        {{ok, _}, _}       -> Config;
        {error, {ok, G}}   -> Config#{guard => G};
        {error, error}     -> Config
    end.

-spec maybe_configure_guard(map()) -> ok.
maybe_configure_guard(#{guard := GuardConfig}) when is_map(GuardConfig) ->
    case erlang:whereis(erlkoenig_nft_ct_guard) of
        undefined ->
            logger:warning("erlkoenig_config: erlkoenig_nft_ct_guard not running, "
                           "guard config ignored"),
            ok;
        _Pid ->
            erlkoenig_nft_ct_guard:reconfigure(GuardConfig),
            %% Forward whitelist to threat mesh
            case erlang:whereis(erlkoenig_threat_mesh) of
                undefined -> ok;
                _ ->
                    Whitelist = maps:get(whitelist, GuardConfig, []),
                    erlkoenig_threat_mesh:reconfigure(#{whitelist => Whitelist})
            end,
            ok
    end;
maybe_configure_guard(_) ->
    ok.

%%====================================================================
%% Internal -- Watches
%%====================================================================

-spec start_watch(map()) -> ok.
start_watch(#{counters := Counters, actions := Actions} = Watch) ->
    Family   = maps:get(family, Watch, 1),
    Table    = iolist_to_binary(maps:get(table, Watch, <<"erlkoenig">>)),
    Interval = maps:get(interval, Watch, 2000),
    Name     = iolist_to_binary(maps:get(name, Watch, <<"unnamed">>)),
    CounterBins = [iolist_to_binary(C) || C <- Counters],
    WatchConfig = #{family => Family, table => Table,
                    counters => CounterBins, interval => Interval},
    case erlkoenig_nft_watch:start_link(WatchConfig) of
        {ok, Pid} ->
            Thresholds = maps:get(thresholds, Watch, []),
            ActionFun = compile_actions(Actions, Name),
            lists:foreach(fun(T) ->
                add_threshold(Pid, T, ActionFun)
            end, Thresholds),
            logger:info("erlkoenig_config: watch ~s started (~p counters)",
                        [Name, length(CounterBins)]),
            ok;
        {error, Reason} ->
            logger:warning("erlkoenig_config: failed to start watch ~s: ~p",
                           [Name, Reason]),
            ok
    end;
start_watch(_) ->
    ok.

-spec add_threshold(pid(), tuple(), fun()) -> ok.
add_threshold(Pid, {Counter, _Obj, Metric, Op, Value}, ActionFun) ->
    CounterBin = iolist_to_binary(Counter),
    Id = {CounterBin, Metric},
    erlkoenig_nft_watch:add_threshold(Pid, Id, CounterBin, Metric,
                             {ActionFun, Op, Value});
add_threshold(_Pid, Unknown, _ActionFun) ->
    logger:warning("erlkoenig_config: unknown threshold format: ~p", [Unknown]),
    ok.

-doc """
Compile a list of DSL action atoms into a single action function.

Supported actions:
  log                  - logger:warning with counter details
  {webhook, Url}       - HTTP POST to Url with JSON payload
""".
-spec compile_actions([atom() | tuple()], binary()) -> fun().
compile_actions(Actions, WatchName) ->
    fun(Counter, Metric, Value, Threshold) ->
        lists:foreach(fun(Action) ->
            run_action(Action, WatchName, Counter, Metric, Value, Threshold)
        end, Actions)
    end.

-spec run_action(atom() | tuple(), binary(), binary(), atom(),
                 number(), number()) -> ok.
run_action(log, WatchName, Counter, Metric, Value, Threshold) ->
    logger:warning("[watch:~s] ~s ~p=~p exceeds ~p",
                   [WatchName, Counter, Metric, Value, Threshold]);
run_action({webhook, Url}, WatchName, Counter, Metric, Value, Threshold) ->
    Body = iolist_to_binary(io_lib:format(
        "{\"watch\":\"~s\",\"counter\":\"~s\",\"metric\":\"~s\","
        "\"value\":~p,\"threshold\":~p}",
        [WatchName, Counter, Metric, Value, Threshold])),
    spawn(fun() ->
        case httpc:request(post,
                {binary_to_list(iolist_to_binary(Url)),
                 [], "application/json", Body},
                [{timeout, 5000}], []) of
            {ok, _} -> ok;
            {error, Reason} ->
                logger:warning("[watch:~s] webhook failed: ~p", [WatchName, Reason])
        end
    end),
    ok;
run_action(Unknown, WatchName, _Counter, _Metric, _Value, _Threshold) ->
    logger:warning("[watch:~s] unknown action: ~p", [WatchName, Unknown]).

%%====================================================================
%% Internal -- Delta / Reload
%%====================================================================

-spec stop_by_name(binary()) -> ok.
stop_by_name(Name) ->
    %% Use the wider `_all` set: a container that already terminated
    %% (e.g. transient + clean-exit) still has a live gen_statem we
    %% want to address by name during config reconciliation.
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts_all)
           catch error:_ -> []
           end,
    case find_pid_by_name(Name, Pids) of
        {ok, Pid} ->
            logger:info("erlkoenig_config: stopping container ~s", [Name]),
            erlkoenig:stop(Pid);
        error ->
            ok
    end.

%% Wait until all spawned containers have IPs assigned (= reached running state).
%% Returns IP map #{Name => Ip}. Times out after MaxMs.
-spec wait_for_ips([{binary(), pid()}], non_neg_integer()) -> map().
wait_for_ips(Results, MaxMs) ->
    Deadline = erlang:monotonic_time(millisecond) + MaxMs,
    wait_for_ips_loop(Results, #{}, Deadline).

-spec wait_for_ips_loop([{binary(), pid()}], map(), integer()) -> map().
wait_for_ips_loop([], IpMap, _Deadline) ->
    IpMap;
wait_for_ips_loop(Remaining, IpMap, Deadline) ->
    Now = erlang:monotonic_time(millisecond),
    case Now >= Deadline of
        true ->
            Names = [N || {N, _} <- Remaining],
            logger:warning("erlkoenig_config: timeout waiting for IPs: ~p", [Names]),
            IpMap;
        false ->
            {Found, Still} = lists:partition(fun({_Name, Pid}) ->
                try erlkoenig_ct:get_info(Pid) of
                    #{net_info := #{ip := _}} -> true;
                    _ -> false
                catch _:_ -> false
                end
            end, Remaining),
            NewIps = lists:foldl(fun({Name, Pid}, Acc) ->
                try erlkoenig_ct:get_info(Pid) of
                    #{net_info := #{ip := Ip}} -> Acc#{Name => Ip};
                    _ -> Acc
                catch _:_ -> Acc
                end
            end, IpMap, Found),
            case Still of
                [] -> NewIps;
                _  ->
                    timer:sleep(25),
                    wait_for_ips_loop(Still, NewIps, Deadline)
            end
    end.


%% `force_stop_zone_containers/1' lives in erlkoenig_config_zone.

-spec find_pid_by_name(binary(), [pid()]) -> {ok, pid()} | error.
find_pid_by_name(_Name, []) -> error;
find_pid_by_name(Name, [Pid | Rest]) ->
    try erlkoenig_ct:get_info(Pid) of
        #{name := N} when N =:= Name -> {ok, Pid};
        _ -> find_pid_by_name(Name, Rest)
    catch _:_ -> find_pid_by_name(Name, Rest)
    end.

%%====================================================================
%% Internal -- Config State (ETS)
%%====================================================================

%% Config cache survives across `load/1` calls via persistent_term.
%% Previously this was a named ETS table created on demand; because
%% `load/1` runs inside a transient rpc:call process, the table died
%% with every call, so reconciliation always saw `undefined` as
%% OldConfig — leading to zombie pod supervisors and spurious
%% re-spawns on every reload. persistent_term is owned by the VM, so
%% it survives both rpc processes and beam restarts' callers.
store_config(File, Config) ->
    persistent_term:put({?CONFIG_TAB, File}, Config).

get_stored_config(File) ->
    persistent_term:get({?CONFIG_TAB, File}, undefined).
