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

-export([load/1, validate/1, reload/1, parse/1]).

-ifdef(TEST).
-export([resolve_host_refs/2, find_all_replica_ips/3]).
-endif.

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
            {error, {invalid_format, TermFile}};
        {error, Reason} ->
            {error, {read_failed, TermFile, Reason}}
    end.

-doc "Validate a config file (parse + check required fields).".
-spec validate(file:filename()) -> ok | {error, term()}.
validate(TermFile) ->
    case parse(TermFile) of
        {ok, Config} ->
            validate_config(Config);
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
    maybe
        {ok, Config} ?= parse(TermFile),
        ok ?= validate_config(Config),
        _ = ensure_config_tab(),
        OldConfig = get_stored_config(TermFile),
        Result = apply_config_with_reconciliation(OldConfig, Config),
        store_config(TermFile, Config),
        erlkoenig_events:notify({config_loaded, TermFile, Config}),
        Result
    else
        {error, _} = Err ->
            erlkoenig_events:notify({config_failed, TermFile, Err}),
            Err
    end.

-doc "Reload a config file. Alias for load/1 (both are idempotent).".
-spec reload(file:filename()) -> {ok, [{binary(), pid()}]} | {error, term()}.
reload(TermFile) ->
    load(TermFile).

%%====================================================================
%% Internal -- Validation
%%====================================================================

-spec validate_config(term()) -> ok | {error, term()}.
validate_config(Config) when is_map(Config) ->
    %% Unified format: #{images, firewall, zones, steering, ct_guard, watch}
    %% Legacy format:  #{containers, watches, guard}
    %% Both are valid. Zones contain containers; legacy has flat container list.
    case maps:find(zones, Config) of
        {ok, Zones} when is_list(Zones) ->
            validate_zones(Zones);
        {ok, _} ->
            {error, {invalid_type, zones, expected_list}};
        error ->
            %% Try legacy format
            case maps:find(containers, Config) of
                {ok, Containers} when is_list(Containers) ->
                    validate_containers(Containers);
                {ok, _} ->
                    {error, {invalid_type, containers, expected_list}};
                error ->
                    ok
            end
    end;
validate_config(_) ->
    {error, invalid_config}.

-spec validate_zones(list()) -> ok | {error, term()}.
validate_zones([]) -> ok;
validate_zones([#{name := _, containers := Cts} | Rest]) when is_list(Cts) ->
    case validate_containers(Cts) of
        ok -> validate_zones(Rest);
        Err -> Err
    end;
validate_zones([#{name := _, deployments := Deps} | Rest]) when is_list(Deps) ->
    %% New format: zone with pod deployments (containers come from pods)
    validate_zones(Rest);
validate_zones([#{name := _} | Rest]) ->
    %% Zone with no containers and no deployments (isolated or chains-only)
    validate_zones(Rest);
validate_zones([Bad | _]) ->
    {error, {invalid_zone, Bad}}.

-spec validate_containers(list()) -> ok | {error, term()}.
validate_containers([]) -> ok;
validate_containers([#{name := Name, binary := Binary} | Rest])
  when is_list(Name), is_list(Binary) ->
    validate_containers(Rest);
validate_containers([#{name := Name, binary := Binary} | Rest])
  when is_binary(Name), is_binary(Binary) ->
    validate_containers(Rest);
validate_containers([Bad | _]) ->
    {error, {invalid_container, Bad}}.

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

    %% 2. Stop removed containers FIRST (before zone cleanup)
    AllContainers = flatten_containers(Config),
    DeclaredNames = [iolist_to_binary(maps:get(name, C)) || C <- AllContainers],
    RunningNames = container_names_from_old(OldConfig),
    ToStop = RunningNames -- DeclaredNames,
    lists:foreach(fun(Name) ->
        logger:info("erlkoenig_config: stopping removed container ~s", [Name]),
        stop_by_name(Name)
    end, ToStop),
    %% Give containers time to exit and release veths/IPs
    case ToStop of [] -> ok; _ -> timer:sleep(1000) end,

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
                force_stop_zone_containers(Z),
                timer:sleep(500),
                erlkoenig_zone:destroy(Z);
            {error, Reason} ->
                logger:warning("erlkoenig_config: zone ~s destroy failed: ~p", [Z, Reason])
        end
    end, StaleZones),
    Report2 = ensure_zones(Zones, Report1),

    %% 3b. Rebuild nft table with zone-aware bridges
    ZoneNftConfigs = [begin
        ZName = iolist_to_binary(maps:get(name, Z, <<"default">>)),
        Bridge = iolist_to_binary(maps:get(bridge, Z,
                    <<"ek_br_", ZName/binary>>)),
        #{bridge => Bridge,
          subnet => maps:get(subnet, Z, {10, 0, 0, 0}),
          netmask => maps:get(netmask, Z, 24),
          policy => allow_outbound}
    end || Z <- Zones],
    case ZoneNftConfigs of
        [] -> ok;
        _ ->
            _ = erlkoenig_firewall_nft:setup_table(ZoneNftConfigs),
            _ = os:cmd("ip link delete erlkoenig_br0 2>/dev/null"),
            ok
    end,

    %% 3c. Apply zone network policy (old format only — new format deferred to 6b)
    lists:foreach(fun(#{allows := _, bridge := Bridge} = Zone) ->
        BridgeBin = iolist_to_binary(Bridge),
        erlkoenig_firewall_nft:apply_zone_allows(Zone, BridgeBin);
       (_) -> ok
    end, Zones),

    %% 4. Apply host firewall (skipped when nft_tables present — ADR-0015)
    Report3 = case maps:is_key(nft_tables, Config) of
        true -> Report2#{firewall => nft_tables};
        false -> maybe_apply_firewall(Config, Report2)
    end,

    %% 5. Apply guard + watches
    maybe_configure_guard(Config),
    Watches = maps:get(watches, Config, maps:get(watch, Config, [])),
    WatchList = if is_list(Watches) -> Watches;
                   is_map(Watches) -> [Watches];
                   true -> []
                end,
    lists:foreach(fun start_watch/1, WatchList),

    %% Start new containers (not already running)
    %% Group by pod instance for pod-supervised startup
    ToStart = DeclaredNames -- RunningNames,
    Pods = maps:get(pods, Config, []),
    HasNftTables = maps:is_key(nft_tables, Config),
    %% When nft_tables present, containers don't get auto-generated firewall chains
    NewContainers0 = [Ct || Ct <- AllContainers,
                      lists:member(iolist_to_binary(maps:get(name, Ct)), ToStart)],
    NewContainers = case HasNftTables of
        true -> [Ct#{firewall => skip_firewall} || Ct <- NewContainers0];
        false -> NewContainers0
    end,
    Results = spawn_pods(NewContainers, Pods),

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
                apply_zone_chains(Zone, IpMap);
               (_) -> ok
            end, Zones),
            apply_pod_forward_chains(Pods, Zones, Results);
        _ ->
            %% New path: nft-transparent DSL (ADR-0015)
            %% nft_tables define ALL firewall rules — skip legacy chain generation
            VethMap = build_veth_map(Results),
            apply_nft_tables(NftTables, IpMap, VethMap, Pods, Zones)
    end,

    %% 7. Apply steering
    Report4 = maybe_apply_steering(Config, AllContainers, Report3),

    %% 8. Log report
    Started = length(Results),
    Stopped = length(ToStop),
    Kept = length(DeclaredNames) - Started,
    logger:info("erlkoenig_config: reconciled — ~p started, ~p stopped, ~p kept",
                [Started, Stopped, Kept]),
    log_deploy_report(Report4, Started, length(AllContainers)),

    {ok, Results}.

-spec container_names_from_old(map() | undefined) -> [binary()].
container_names_from_old(undefined) -> [];
container_names_from_old(Config) -> container_names(Config).

%% Flatten containers from zones or legacy format.
%% New format: zones may have `deployments` referencing pods.
%% Pod expansion: each replica gets a unique name and auto-assigned IP.
-spec flatten_containers(map()) -> [map()].
flatten_containers(Config) ->
    Pods = maps:get(pods, Config, []),
    PodMap = maps:from_list([{iolist_to_binary(maps:get(name, P)), P} || P <- Pods]),
    case maps:find(zones, Config) of
        {ok, Zones} when is_list(Zones) ->
            lists:flatmap(fun(Zone) ->
                flatten_zone_containers(Zone, PodMap)
            end, Zones);
        _ ->
            case maps:find(containers, Config) of
                {ok, Containers} -> Containers;
                _ -> []
            end
    end.

%% Flatten containers from a single zone — handles both old (containers)
%% and new (deployments) formats.
-spec flatten_zone_containers(map(), map()) -> [map()].
flatten_zone_containers(#{deployments := Deps} = Zone, PodMap) ->
    ZoneName = iolist_to_binary(maps:get(name, Zone, <<"default">>)),
    ZoneAtom = binary_to_atom(ZoneName),
    Subnet = maps:get(subnet, Zone, {10, 0, 0, 0}),
    {Sa, Sb, Sc, _} = Subnet,

    %% Expand all deployments, tracking IP counter across pods
    {AllContainers, _} = lists:foldl(fun(#{pod := PodName, replicas := Replicas}, {Acc, IpCounter}) ->
        PodBin = iolist_to_binary(PodName),
        case maps:find(PodBin, PodMap) of
            {ok, Pod} ->
                PodContainers = maps:get(containers, Pod, []),
                {NewCts, NextIp} = expand_replicas(PodBin, PodContainers, Replicas,
                                                    ZoneAtom, {Sa, Sb, Sc}, IpCounter, Pod),
                {Acc ++ NewCts, NextIp};
            error ->
                logger:warning("erlkoenig_config: unknown pod ~s in zone ~s",
                               [PodBin, ZoneName]),
                {Acc, IpCounter}
        end
    end, {[], 2}, Deps),

    %% Also include any standalone containers in the zone
    Standalone = maps:get(containers, Zone, []),
    StandaloneTagged = [Ct#{zone => ZoneAtom} || Ct <- Standalone],

    AllContainers ++ StandaloneTagged;

flatten_zone_containers(#{containers := Cts} = Zone, _PodMap) ->
    ZoneName = maps:get(name, Zone, <<"default">>),
    ZoneAtom = binary_to_atom(iolist_to_binary(ZoneName)),
    [Ct#{zone => ZoneAtom} || Ct <- Cts];

flatten_zone_containers(_, _) ->
    [].

%% Expand N replicas of a pod into concrete containers with IPs.
-spec expand_replicas(binary(), [map()], pos_integer(), atom(),
                      {byte(), byte(), byte()}, pos_integer(), map()) ->
    {[map()], pos_integer()}.
expand_replicas(PodName, PodContainers, Replicas, ZoneAtom,
                {Sa, Sb, Sc}, IpStart, Pod) ->
    PodChains = maps:get(chains, Pod, []),
    lists:foldl(fun(ReplicaIdx, {Acc, IpCounter}) ->
        {Cts, NextIp} = lists:foldl(fun(Ct, {CtAcc, Ip}) ->
            CtName = maps:get(name, Ct, <<"unnamed">>),
            %% Name: podname-N-containername
            FullName = iolist_to_binary([PodName, "-",
                integer_to_binary(ReplicaIdx), "-",
                iolist_to_binary(CtName)]),
            CtIp = {Sa, Sb, Sc, Ip},
            Expanded = Ct#{
                name => FullName,
                ip => CtIp,
                zone => ZoneAtom,
                pod => PodName,
                pod_instance => ReplicaIdx
            },
            %% Attach per-container firewall if pod defines it
            Expanded2 = case maps:find(firewall, Ct) of
                {ok, _} -> Expanded;
                error -> Expanded
            end,
            {CtAcc ++ [Expanded2], Ip + 1}
        end, {[], IpCounter}, PodContainers),
        %% TODO: pod-level chains (forward rules between containers)
        %% will be applied via erlkoenig_firewall_nft when we implement
        %% @ref resolution. For now, per-container chains work.
        _ = PodChains,
        {Acc ++ Cts, NextIp}
    end, {[], IpStart}, lists:seq(0, Replicas - 1)).

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

%% Ensure zones exist (bridge + IP pool + DNS)
-spec ensure_zones(list(), map()) -> map().
ensure_zones(Zones, Report) ->
    Results = lists:map(fun(#{name := Name} = Zone) ->
        ZoneAtom = binary_to_atom(iolist_to_binary(Name)),
        ZoneConfig = #{
            bridge  => iolist_to_binary(maps:get(bridge, Zone, <<"ek_br_", Name/binary>>)),
            subnet  => maps:get(subnet, Zone, {10, 0, 0, 0}),
            gateway => maps:get(gateway, Zone, {10, 0, 0, 1}),
            netmask => maps:get(netmask, Zone, 24),
            policy  => maps:get(policy, Zone, allow_outbound)
        },
        try erlkoenig_zone:zone_config(ZoneAtom) of
            OldCfg ->
                %% Zone exists — check if config changed (subnet/gateway)
                OldSubnet = maps:get(subnet, OldCfg, undefined),
                NewSubnet = maps:get(subnet, ZoneConfig),
                case OldSubnet =:= NewSubnet of
                    true ->
                        {Name, already_exists};
                    false ->
                        %% Subnet changed — destroy and recreate
                        logger:info("erlkoenig_config: zone ~s subnet changed ~p -> ~p, recreating",
                                    [Name, OldSubnet, NewSubnet]),
                        force_stop_zone_containers(ZoneAtom),
                        timer:sleep(500),
                        _ = erlkoenig_zone:destroy(ZoneAtom),
                        case erlkoenig_zone:create(ZoneAtom, ZoneConfig) of
                            ok -> {Name, recreated};
                            {error, R} -> {Name, {error, R}}
                        end
                end
        catch
            error:{unknown_zone, _} ->
                case erlkoenig_zone:create(ZoneAtom, ZoneConfig) of
                    ok -> {Name, created};
                    {error, R} -> {Name, {error, R}}
                end
        end;
       (Bad) -> {<<"?">>, {error, {invalid_zone, Bad}}}
    end, Zones),
    Report#{zones => maps:from_list(Results)}.

%% Apply host firewall via erlkoenig_nft
-spec maybe_apply_firewall(map(), map()) -> map().
maybe_apply_firewall(#{firewall := FwConfig}, Report) when is_map(FwConfig) ->
    case erlang:whereis(erlkoenig_nft_firewall) of
        undefined ->
            logger:warning("erlkoenig_config: erlkoenig_nft_firewall not running"),
            Report#{firewall => skipped};
        _Pid ->
            %% Write config to the path erlkoenig_nft_firewall reads from,
            %% then trigger reload. This keeps the firewall gen_server
            %% as the single owner of the nftables state.
            FwPath = case erlkoenig_nft_config:config_path() of
                {ok, P} -> P;
                {error, _} -> "etc/firewall.term"
            end,
            ok = filelib:ensure_dir(FwPath),
            Formatted = io_lib:format("~tp.~n", [FwConfig]),
            case file:write_file(FwPath, Formatted) of
                ok ->
                    case erlkoenig_nft:reload() of
                        ok ->
                            Table = maps:get(table, FwConfig, <<"?">>),
                            logger:info("erlkoenig_config: firewall ~s applied", [Table]),
                            Report#{firewall => ok};
                        {error, Reason} ->
                            logger:warning("erlkoenig_config: firewall reload failed: ~p",
                                           [Reason]),
                            Report#{firewall => {error, Reason}}
                    end;
                {error, WriteErr} ->
                    logger:warning("erlkoenig_config: cannot write firewall config: ~p",
                                   [WriteErr]),
                    Report#{firewall => {error, WriteErr}}
            end
    end;
maybe_apply_firewall(_, Report) ->
    Report.

%% Apply BPF steering
-spec maybe_apply_steering(map(), [map()], map()) -> map().
maybe_apply_steering(#{steering := #{services := Services, routes := Routes}},
                     AllContainers, Report) ->
    %% Register routes (container name → IP + ifindex)
    lists:foreach(fun(ContainerName) ->
        NameBin = iolist_to_binary(ContainerName),
        case find_container_ip(NameBin, AllContainers) of
            {ok, Ip} ->
                %% ifindex resolved at runtime from host veth
                logger:info("erlkoenig_config: steering route ~s → ~p (deferred)",
                            [NameBin, Ip]);
            error ->
                logger:warning("erlkoenig_config: steering route ~s: container not found",
                               [NameBin])
        end
    end, Routes),

    %% Register services
    lists:foreach(fun(#{name := Name, vip := Vip, port := Port, proto := Proto,
                        backends := Backends}) ->
        case erlkoenig_steering:add_service(Vip, Port, Proto) of
            {ok, _SvcId} ->
                logger:info("erlkoenig_config: steering service ~p added", [Name]),
                %% Backends resolved later when containers are running
                logger:info("erlkoenig_config: backends ~p deferred until containers ready",
                            [Backends]);
            {error, not_running} ->
                logger:warning("erlkoenig_config: ebpfd not running, steering skipped");
            {error, Reason} ->
                logger:warning("erlkoenig_config: steering service ~p failed: ~p",
                               [Name, Reason])
        end
    end, Services),
    Report#{steering => ok};
maybe_apply_steering(_, _, Report) ->
    Report.

-spec find_container_ip(binary(), [map()]) -> {ok, tuple()} | error.
find_container_ip(Name, Containers) ->
    case lists:search(fun(#{name := N}) ->
        iolist_to_binary(N) =:= Name
    end, Containers) of
        {value, #{ip := Ip}} -> {ok, Ip};
        _ -> error
    end.

-spec log_deploy_report(map(), non_neg_integer(), non_neg_integer()) -> ok.
log_deploy_report(Report, Started, Total) ->
    logger:info("erlkoenig_config: deploy complete — ~p/~p containers started",
                [Started, Total]),
    maps:foreach(fun
        (images, Imgs) ->
            maps:foreach(fun(N, ok) ->
                logger:info("  image ~s: OK", [N]);
               (N, {not_found, P}) ->
                logger:warning("  image ~s: NOT FOUND (~s)", [N, P])
            end, Imgs);
        (zones, Zs) ->
            maps:foreach(fun(N, S) ->
                logger:info("  zone ~s: ~p", [N, S])
            end, Zs);
        (firewall, S) ->
            logger:info("  firewall: ~p", [S]);
        (steering, S) ->
            logger:info("  steering: ~p", [S]);
        (_, _) -> ok
    end, Report).

%% Group containers by pod instance and start via pod supervisors.
%% Containers without a pod field are started individually (isolated).
-spec spawn_pods([map()], [map()]) -> [{binary(), pid()}].
spawn_pods(Containers, PodDefs) ->
    %% Build strategy lookup: PodName → OTP strategy
    StrategyMap = lists:foldl(fun(PodDef, Acc) ->
        PodName = iolist_to_binary(maps:get(name, PodDef, <<>>)),
        Strategy = maps:get(strategy, PodDef, one_for_one),
        Acc#{PodName => Strategy}
    end, #{}, PodDefs),

    %% Group by {pod, pod_instance}
    Groups = lists:foldl(fun(Ct, Acc) ->
        Key = case {maps:get(pod, Ct, undefined), maps:get(pod_instance, Ct, undefined)} of
            {undefined, _} -> {standalone, iolist_to_binary(maps:get(name, Ct))};
            {Pod, Inst}    -> {iolist_to_binary(Pod), Inst}
        end,
        maps:update_with(Key, fun(L) -> L ++ [Ct] end, [Ct], Acc)
    end, #{}, Containers),

    %% Start each group
    lists:flatmap(fun({{standalone, _Name}, [Ct]}) ->
        case spawn_container(Ct) of
            {true, Result} -> [Result];
            false -> []
        end;
    ({{PodName, Inst}, Cts}) ->
        PodInstName = <<PodName/binary, "-", (integer_to_binary(Inst))/binary>>,
        Strategy = maps:get(PodName, StrategyMap, one_for_one),
        Children = [{iolist_to_binary(maps:get(binary, Ct)), build_spawn_opts(Ct)}
                    || Ct <- Cts],
        %% Build name→index mapping from Cts list
        CtNames = [iolist_to_binary(maps:get(name, Ct)) || Ct <- Cts],
        case erlkoenig_sup:start_pod(PodInstName, Strategy, Children) of
            {ok, PodPid} ->
                logger:info("erlkoenig_config: started pod ~s (strategy=~p, ~p containers)",
                            [PodInstName, Strategy, length(Children)]),
                %% Collect child PIDs — match by position (same order as Children)
                ChildPids = supervisor:which_children(PodPid),
                %% which_children returns in reverse start order
                OrderedPids = lists:reverse([Pid || {_, Pid, _, _} <- ChildPids,
                                                    is_pid(Pid)]),
                [{N, P} || {N, P} <- lists:zip(CtNames, OrderedPids)];
            {error, Reason} ->
                logger:warning("erlkoenig_config: failed to start pod ~s: ~p",
                               [PodInstName, Reason]),
                []
        end
    end, maps:to_list(Groups)).

-spec spawn_container(map()) -> {true, {binary(), pid()}} | false.
spawn_container(#{name := Name, binary := Binary} = Ct) ->
    SpawnOpts = build_spawn_opts(Ct),
    BinPath = iolist_to_binary(Binary),
    case erlkoenig:spawn(BinPath, SpawnOpts) of
        {ok, Pid} ->
            logger:info("erlkoenig_config: spawned ~s (~p)", [Name, Pid]),
            maybe_add_health_check(Pid, Ct),
            {true, {iolist_to_binary(Name), Pid}};
        {error, Reason} ->
            logger:warning("erlkoenig_config: failed to spawn ~s: ~p",
                           [Name, Reason]),
            false
    end.

%%====================================================================
%% Internal -- nft_tables (ADR-0015)
%%====================================================================

%% Build {PodName, ContainerName} → HostVeth map from spawned containers.
-spec build_veth_map([{binary(), pid()}]) -> map().
build_veth_map(Results) ->
    lists:foldl(fun({Name, Pid}, Acc) ->
        try erlkoenig:inspect(Pid) of
            #{net_info := #{host_veth := Veth}} ->
                %% Name = "web-0-nginx" → extract pod="web", ct="nginx"
                case parse_container_name(Name) of
                    {Pod, _Idx, Ct} -> Acc#{{Pod, Ct} => Veth};
                    _ -> Acc
                end;
            _ -> Acc
        catch _:_ -> Acc
        end
    end, #{}, Results).

%% Parse "web-0-nginx" → {"web", "0", "nginx"}
-spec parse_container_name(binary()) -> {binary(), binary(), binary()} | error.
parse_container_name(Name) ->
    case binary:split(Name, <<"-">>, [global]) of
        Parts when length(Parts) >= 3 ->
            Pod = hd(Parts),
            Ct = lists:last(Parts),
            Idx = iolist_to_binary(lists:join(<<"-">>, tl(lists:droplast(Parts)))),
            {Pod, Idx, Ct};
        _ -> error
    end.

%% Build {PodName, ContainerName} → [IP, ...] map for replica expansion.
-spec build_replica_ip_map(map(), [map()], [map()]) -> map().
build_replica_ip_map(IpMap, _Pods, _Zones) ->
    %% IpMap: "web-0-nginx" → {10,0,0,2}
    %% We need: {"web","nginx"} → [{10,0,0,2}, {10,0,0,3}, ...]
    maps:fold(fun(Name, Ip, Acc) ->
        case parse_container_name(Name) of
            {Pod, _Idx, Ct} ->
                Key = {Pod, Ct},
                maps:update_with(Key, fun(Ips) -> Ips ++ [Ip] end, [Ip], Acc);
            _ -> Acc
        end
    end, #{}, IpMap).

%% Apply nft_tables from the DSL config.
-spec apply_nft_tables([map()], map(), map(), [map()], [map()]) -> ok.
apply_nft_tables([], _, _, _, _) -> ok;
apply_nft_tables(Tables, IpMap, VethMap, Pods, Zones) ->
    ReplicaIpMap = build_replica_ip_map(IpMap, Pods, Zones),
    lists:foreach(fun(Table) ->
        apply_nft_table(Table, VethMap, ReplicaIpMap)
    end, Tables).

apply_nft_table(#{name := TableName, chains := Chains} = Table, VethMap, ReplicaIpMap) ->
    Family = maps:get(family, Table, inet),
    FamilyNum = case Family of inet -> 1; ip -> 2; ip6 -> 10; _ -> 1 end,
    TableBin = iolist_to_binary(TableName),
    Counters = maps:get(counters, Table, []),

    %% 0. Ensure the table exists (idempotent).
    %% Do NOT delete+recreate the table — that wipes chains/sets/maps
    %% from other subsystems (erlkoenig_firewall_nft, ct_guard).
    %% Instead, selectively remove only DSL-owned objects, then re-add.
    _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
        fun(S) -> nft_table:add(FamilyNum, TableBin, S) end
    ]),

    %% 1. Build the new state first (we need map names to know what to delete)
    %% Clear tmp map name accumulator before compilation
    persistent_term:put(erlkoenig_dsl_map_names_tmp, []),
    %% Regular chains first (jump targets), then base chains
    OrderedChains = lists:sort(fun(A, _B) ->
        not maps:is_key(hook, A)
    end, Chains),
    %% Compile all chains → {ChainCreates, MapCreates, RuleCreates}
    {AllChainCreates, AllMapCreates, AllRuleCreates} = lists:foldl(
        fun(Chain, {CAcc, MAcc, RAcc}) ->
            {ChainMsg, MapMsgs, RuleMsgs} = compile_nft_chain_split(
                FamilyNum, TableBin, Chain, VethMap, ReplicaIpMap),
            {CAcc ++ ChainMsg, MAcc ++ MapMsgs, RAcc ++ RuleMsgs}
        end, {[], [], []}, OrderedChains),

    %% 2. Collect names of DSL objects for selective cleanup.
    %% Chain names from the config, map names from the compiled output.
    ChainNames = [iolist_to_binary(maps:get(name, C)) || C <- Chains],
    NewMapNames = collect_compiled_map_names(AllMapCreates),

    %% 3. Also collect map names from the persistent_term (previous load's maps).
    %% On reload, container IPs change → map names change (phash2 of targets).
    %% We need to delete OLD maps, not just new ones.
    OldMapNames = persistent_term:get({erlkoenig_dsl_maps, TableBin}, []),

    %% 4. Selectively delete old DSL objects.
    %% Order: flush chain rules → delete chains → delete maps.
    %% Maps cannot be deleted while rules reference them.
    %% Each operation is a separate batch because non-existent objects
    %% cause the whole batch to fail with enoent (first load: nothing exists).
    lists:foreach(fun(CN) ->
        _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_delete:flush_chain(FamilyNum, TableBin, CN, S) end
        ]),
        _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_delete:chain(FamilyNum, TableBin, CN, S) end
        ])
    end, ChainNames),
    AllMapNames = lists:usort(OldMapNames ++ NewMapNames),
    lists:foreach(fun(MN) ->
        _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
            fun(S) -> nft_delete:set(FamilyNum, TableBin, MN, S) end
        ])
    end, AllMapNames),

    %% 5. Remember current map names for next reload
    persistent_term:put({erlkoenig_dsl_maps, TableBin}, NewMapNames),

    %% 4. Create counters (idempotent — CREATE flag means no error if exists)
    CounterMsgs = [fun(S) ->
        nft_object:add_counter(FamilyNum, TableBin, iolist_to_binary(C), S)
    end || C <- Counters],

    %% 5. Single atomic batch: counters → maps+elements → chains → rules.
    %% Maps and elements use SET_ID for same-batch correlation.
    %% Rules use SET_ID in lookup expressions to reference pending maps.
    AllMsgs = CounterMsgs ++ AllMapCreates ++ AllChainCreates ++ AllRuleCreates,
    logger:notice("erlkoenig_config: nft_table ~s: ~p counters, ~p maps, ~p chains, ~p rules",
                [TableName, length(CounterMsgs), length(AllMapCreates),
                 length(AllChainCreates), length(AllRuleCreates)]),
    case AllMsgs of
        [] ->
            logger:info("erlkoenig_config: nft_table ~s: empty (no chains)", [TableName]);
        _ ->
            case nfnl_server:apply_msgs(erlkoenig_nft_srv, AllMsgs) of
                ok ->
                    logger:notice("erlkoenig_config: nft_table ~s applied ok", [TableName]),
                    erlkoenig_events:notify({firewall_applied, TableName});
                {error, Reason} ->
                    logger:warning("erlkoenig_config: nft_table ~s batch failed: ~p",
                                   [TableName, Reason]),
                    erlkoenig_events:notify({firewall_failed, TableName, Reason})
            end
    end;
apply_nft_table(_, _, _) -> ok.

compile_nft_chain_split(Family, Table, #{name := Name, rules := Rules} = Chain,
                        VethMap, ReplicaIpMap) ->
    ChainBin = iolist_to_binary(Name),

    %% Create chain (base or regular)
    ChainMsg = case maps:find(hook, Chain) of
        {ok, Hook} ->
            Type = maps:get(type, Chain, filter),
            Priority = priority_to_int(maps:get(priority, Chain, filter)),
            Policy = maps:get(policy, Chain, accept),
            [fun(S) -> nft_chain:add(Family, #{
                table => Table, name => ChainBin,
                hook => Hook, type => Type,
                priority => Priority, policy => Policy
            }, S) end];
        error ->
            [fun(S) -> nft_chain:add_regular(Family, #{
                table => Table, name => ChainBin
            }, S) end]
    end,

    %% Phase 1: Expand all rules (resolve veth_of, replica_ips)
    AllExpanded = lists:flatmap(fun({Action, Opts}) ->
        expand_nft_rule(Action, Opts, VethMap, ReplicaIpMap)
    end, Rules),

    %% Phase 2: Collapse eligible rules into verdict maps
    %% - accept rules with saddr+daddr+tcp → concat vmap
    %% - jump rules with iif → iifname vmap
    {CollapsedRules, VmapMsgs} = maybe_collapse_to_vmaps(
        AllExpanded, Family, Table, ChainBin),

    %% Phase 3: Compile remaining rules (including non-collapsible ones)
    {RuleMsgs, MapMsgs} = lists:foldl(fun(Rule, {RA, MA}) ->
        try
            {Rule2, ExtraMaps} = maybe_create_lb_map(Rule, Family, Table),
            Compiled = erlkoenig_firewall_nft:compile_rule(Rule2),
            RuleMsg = nft_encode:rule_fun(Family, Table, ChainBin, Compiled),
            {[RuleMsg | RA], ExtraMaps ++ MA}
        catch C:Err ->
            logger:warning("erlkoenig_config: nft rule compile error: ~p:~p for ~p",
                           [C, Err, Rule]),
            {RA, MA}
        end
    end, {[], []}, CollapsedRules),

    %% MapMsgs: dnat_lb maps. VmapMsgs: concat/iifname vmaps.
    %% RuleMsgs are accumulated with prepend, so reverse.
    {ChainMsg, VmapMsgs ++ MapMsgs, lists:reverse(RuleMsgs)}.

%% ===================================================================
%% VMap Collapsing — replace repetitive rules with O(1) lookups
%% ===================================================================

%% Scan expanded rules and collapse eligible patterns into verdict maps:
%%  - Multiple {rule, accept, #{saddr, daddr, tcp}} → concat vmap
%%  - Multiple {rule, jump, #{iif, chain}} → iifname vmap
-spec maybe_collapse_to_vmaps([term()], non_neg_integer(), binary(), binary()) ->
    {[term()], [fun()]}.
maybe_collapse_to_vmaps(Rules, Family, Table, ChainBin) ->
    %% Count collapsible rules (saddr+daddr+tcp accept)
    Collapsible = [R || {rule, accept, #{saddr := _, daddr := _, tcp := _}} = R <- Rules],
    case length(Collapsible) >= 3 of
        true ->
            VmapName = <<"__fwd_", ChainBin/binary>>,
            VmapId = erlang:phash2(VmapName) band 16#FFFF,
            %% Create concat vmap
            CreateVmap = fun(S) ->
                nft_set:add_concat_vmap(Family, #{
                    table => Table,
                    name => VmapName,
                    fields => [ipv4_addr, ipv4_addr, inet_service],
                    id => VmapId
                }, VmapId, S)
            end,
            %% Collect elements from collapsible rules
            Elements = lists:filtermap(fun({rule, accept, Opts}) ->
                case {maps:find(saddr, Opts), maps:find(daddr, Opts), maps:find(tcp, Opts)} of
                    {{ok, SA}, {ok, DA}, {ok, Port}} ->
                        SABin = ip_to_binary(SA),
                        DABin = ip_to_binary(DA),
                        Key = <<SABin/binary, DABin/binary, Port:16/big, 0:16>>,
                        {true, {Key, accept}};
                    _ -> false
                end
            end, Collapsible),
            AddElems = fun(S) ->
                nft_set_elem:add_vmap_elems(Family, Table, VmapName, Elements, S)
            end,
            %% Track map name for cleanup
            OldNames = persistent_term:get(erlkoenig_dsl_map_names_tmp, []),
            persistent_term:put(erlkoenig_dsl_map_names_tmp, [VmapName | OldNames]),
            %% Replace collapsible rules in-place, preserving order.
            %% First collapsible rule becomes the vmap lookup,
            %% subsequent collapsible rules are removed.
            LookupRule = {rule, vmap_concat_lookup, #{
                set => VmapName,
                set_id => VmapId,
                fields => [ip_saddr, ip_daddr, tcp_dport]
            }},
            CollapsibleSet = sets:from_list(Collapsible),
            {Replaced, _} = lists:foldl(fun(Rule, {Acc, Inserted}) ->
                case sets:is_element(Rule, CollapsibleSet) of
                    true when not Inserted ->
                        {[LookupRule | Acc], true};
                    true ->
                        {Acc, Inserted};  %% skip subsequent collapsible rules
                    false ->
                        {[Rule | Acc], Inserted}
                end
            end, {[], false}, Rules),
            {lists:reverse(Replaced), [CreateVmap, AddElems]};
        false ->
            {Rules, []}
    end.


%% Expand a single nft rule, resolving {:veth_of,...} and {:replica_ips,...}.
%% Returns a list of rules (one per replica IP when expanded).
-spec expand_nft_rule(atom(), map(), map(), map()) -> [term()].

expand_nft_rule(jump, #{to := Target} = Opts, VethMap, _ReplicaIpMap) ->
    TargetBin = iolist_to_binary(Target),
    case maps:find(iifname, Opts) of
        {ok, {veth_of, Pod, Ct}} ->
            Veths = maps:fold(fun({P, C}, Veth, Acc) when P =:= Pod, C =:= Ct ->
                [Veth | Acc];
            (_, _, Acc) -> Acc
            end, [], VethMap),
            case Veths of
                [] ->
                    logger:warning("erlkoenig_config: veth_of ~s.~s not found", [Pod, Ct]),
                    [];
                _ ->
                    [{rule, jump, #{iif => V, chain => TargetBin}} || V <- Veths]
            end;
        _ ->
            [{rule, jump, #{chain => TargetBin}}]
    end;

%% dnat_lb: collect ALL replica IPs into one rule (not expanded to N rules)
expand_nft_rule(dnat_lb, Opts, VethMap, ReplicaIpMap) ->
    Port = maps:get(port, Opts, 0),
    Targets = case maps:get(targets, Opts, undefined) of
        {replica_ips, Pod, Ct} ->
            IpList = maps:get({Pod, Ct}, ReplicaIpMap, []),
            [ip_to_binary(Ip) || Ip <- IpList];
        _ -> []
    end,
    BaseOpts = maps:fold(fun
        (iifname, {veth_of, P, C}, Acc) ->
            case maps:find({P, C}, VethMap) of
                {ok, Veth} -> Acc#{iif => Veth};
                error -> Acc
            end;
        (iifname, V, Acc) -> Acc#{iif => iolist_to_binary(V)};
        (tcp_dport, P, Acc) -> Acc#{tcp => P};
        (counter, N, Acc) -> Acc#{counter => iolist_to_binary(N)};
        (targets, _, Acc) -> Acc;
        (port, _, Acc) -> Acc;
        (K, V, Acc) -> Acc#{K => V}
    end, #{}, Opts),
    [{rule, dnat_lb, BaseOpts#{targets => Targets, dport => Port}}];

expand_nft_rule(Action, Opts, VethMap, ReplicaIpMap) ->
    %% Resolve all {:veth_of,...} and {:replica_ips,...} in opts
    Resolved = maps:fold(fun
        (iifname, {veth_of, Pod, Ct}, Acc) ->
            case maps:find({Pod, Ct}, VethMap) of
                {ok, Veth} -> Acc#{iif => Veth};
                error -> Acc#{iif => <<"__unresolved__">>}
            end;
        (iifname, V, Acc) -> Acc#{iif => iolist_to_binary(V)};
        (oifname, V, Acc) -> Acc#{oif => iolist_to_binary(V)};
        (oifname_ne, V, Acc) -> Acc#{oif_neq => iolist_to_binary(V)};
        (ip_saddr, {replica_ips, Pod, Ct}, Acc) ->
            Acc#{saddr => {replica_ips, Pod, Ct}};
        (ip_daddr, {replica_ips, Pod, Ct}, Acc) ->
            Acc#{daddr => {replica_ips, Pod, Ct}};
        (ip_saddr, {A,B,C,D,Prefix}, Acc) ->
            Acc#{saddr => {A,B,C,D,Prefix}};
        (ip_daddr, {A,B,C,D,Prefix}, Acc) ->
            Acc#{daddr => {A,B,C,D,Prefix}};
        (tcp_dport, Port, Acc) -> Acc#{tcp => Port};
        (udp_dport, Port, Acc) -> Acc#{udp => Port};
        (ct_state, States, Acc) -> Acc#{ct => hd(States)};
        (log_prefix, Prefix, Acc) -> Acc#{log => Prefix};
        (counter, Name, Acc) -> Acc#{counter => iolist_to_binary(Name)};
        (K, V, Acc) -> Acc#{K => V}
    end, #{}, Opts),

    %% Expand replica_ips into multiple rules (cartesian product)
    SaddrExpand = case maps:find(saddr, Resolved) of
        {ok, {replica_ips, SP, SC}} ->
            maps:get({SP, SC}, ReplicaIpMap, []);
        {ok, Ip} -> [Ip];
        error -> [undefined]
    end,
    DaddrExpand = case maps:find(daddr, Resolved) of
        {ok, {replica_ips, DP, DC}} ->
            maps:get({DP, DC}, ReplicaIpMap, []);
        {ok, Ip2} -> [Ip2];
        error -> [undefined]
    end,

    BaseOpts = maps:without([saddr, daddr], Resolved),

    [{rule, Action, build_rule_opts(BaseOpts, S, D)}
     || S <- SaddrExpand, D <- DaddrExpand].

build_rule_opts(Base, undefined, undefined) -> Base;
build_rule_opts(Base, Saddr, undefined) ->
    Base#{saddr => ip_to_cidr(Saddr)};
build_rule_opts(Base, undefined, Daddr) ->
    Base#{daddr => ip_to_cidr(Daddr)};
build_rule_opts(Base, Saddr, Daddr) ->
    Base#{saddr => ip_to_cidr(Saddr), daddr => ip_to_cidr(Daddr)}.

ip_to_cidr({A,B,C,D}) -> {A,B,C,D,32};
ip_to_cidr({A,B,C,D,P}) -> {A,B,C,D,P};
ip_to_cidr(Other) -> Other.

ip_to_binary({A,B,C,D}) -> <<A,B,C,D>>;
ip_to_binary({A,B,C,D,_Prefix}) -> <<A,B,C,D>>;
ip_to_binary(B) when is_binary(B) -> B.


%% Extract map names from the compiled AllMapCreates list.
%% AllMapCreates contains [CreateMap1, AddElems1, CreateMap2, AddElems2, ...].
%% The CreateMap funs create maps with names like __lb_XXXX.
%% We extract the names by running the split and inspecting maybe_create_lb_map output.
%% Simpler approach: the map names are embedded in the compiled rules via map_name key.
-spec collect_compiled_map_names([fun()]) -> [binary()].
collect_compiled_map_names([]) -> [];
collect_compiled_map_names(_MapMsgs) ->
    %% MapMsgs are [Create, Elems, Create, Elems, ...] pairs.
    %% We can't inspect funs, so we track map names at creation time.
    %% This is called AFTER compile_nft_chain_split, so we extract from
    %% the accumulated data. For now, use the persistent_term set in
    %% maybe_create_lb_map.
    persistent_term:get(erlkoenig_dsl_map_names_tmp, []).

priority_to_int(filter) -> 0;
priority_to_int(dstnat) -> -100;
priority_to_int(srcnat) -> 100;
priority_to_int(mangle) -> -150;
priority_to_int(security) -> 50;
priority_to_int(raw) -> -300;
priority_to_int(N) when is_integer(N) -> N.

-spec maybe_add_health_check(pid(), map()) -> ok.
maybe_add_health_check(Pid, #{health_check := Opts}) when is_map(Opts) ->
    %% Small delay so the container has time to bind its port
    _ = timer:apply_after(2000, erlkoenig_health, add, [Pid, Opts]),
    ok;
maybe_add_health_check(_Pid, _Ct) ->
    ok.

%%====================================================================
%% Internal -- Zone Chains
%%====================================================================

%% Apply zone-level chains as nft rules in the erlkoenig_ct forward chain.
%% Zone chains contain explicit rule terms ({rule, Verdict, Opts}) that get
%% compiled via erlkoenig_firewall_nft:compile_generic_rule and added to
%% the forward chain.
-spec apply_zone_chains(map(), map()) -> ok.
apply_zone_chains(#{chains := Chains} = Zone, IpMap) ->
    ZoneName = maps:get(name, Zone, <<"?">>),
    BridgeName = iolist_to_binary(maps:get(bridge, Zone,
        <<"ek_br_", (iolist_to_binary(ZoneName))/binary>>)),
    Ctx = #{bridge => BridgeName, ip_map => IpMap},
    lists:foreach(fun(#{rules := Rules} = Chain) ->
        ChainTarget = case maps:get(hook, Chain, nil) of
            nil -> <<"forward">>;
            input -> <<"input">>;
            forward -> <<"forward">>;
            postrouting -> <<"postrouting">>;
            prerouting -> <<"prerouting">>;
            output -> <<"output">>
        end,
        %% Named counter + NFLOG for zone forward drops (SPEC-EK-005)
        DropCounterName = <<"zone_", (iolist_to_binary(ZoneName))/binary, "_drop">>,
        NflogGroup = erlkoenig_firewall_nft:next_nflog_group(),
        DropCounterMsg = [fun(S) ->
            nft_object:add_counter(1, <<"erlkoenig">>, DropCounterName, S)
        end],
        RuleMsgs = lists:flatmap(fun(Rule) ->
            Resolved = resolve_host_refs(Rule, Ctx),
            lists:filtermap(fun(R) ->
                try
                    Compiled = erlkoenig_firewall_nft:compile_rule(R),
                    %% Inject counter + nflog on drop rules
                    Compiled2 = erlkoenig_firewall_nft:inject_drop_observability(
                        [Compiled], DropCounterName, NflogGroup),
                    {true, nft_encode:rule_fun(inet, <<"erlkoenig">>,
                        ChainTarget, hd(Compiled2))}
                catch _:Err ->
                    logger:warning("erlkoenig_config: zone ~s rule compile error: ~p for ~p",
                                   [ZoneName, Err, R]),
                    false
                end
            end, Resolved)
        end, Rules),
        case RuleMsgs of
            [] -> ok;
            _ ->
                %% Start NFLOG receiver for this zone's drops
                _ = case erlkoenig_nft_nflog:start_link(NflogGroup) of
                    {ok, _} ->
                        logger:info("erlkoenig_config: nflog group ~p for zone ~s",
                                    [NflogGroup, ZoneName]);
                    {error, NflogErr} ->
                        logger:warning("erlkoenig_config: nflog failed for zone ~s: ~p",
                                        [ZoneName, NflogErr])
                end,
                case nfnl_server:apply_msgs(erlkoenig_nft_srv, DropCounterMsg ++ RuleMsgs) of
                    ok ->
                        logger:info("erlkoenig_config: zone ~s: ~p forward rules applied",
                                    [ZoneName, length(RuleMsgs)]);
                    {error, Reason} ->
                        logger:warning("erlkoenig_config: zone ~s chain apply failed: ~p",
                                       [ZoneName, Reason])
                end
        end
    end, Chains).

%% Resolve symbolic references in rules:
%%   :bridge      → zone bridge name (e.g. "ek_br_test")
%%   :containers  → "vh_*" (all container veths)
%%   "pod.ct"     → IP-based match (saddr/daddr) for pod-qualified names
%%
%% Returns a list of rules. Pod-qualified names with multiple replicas
%% expand to one rule per replica (e.g. "worker.fn" with 5 replicas
%% produces 5 rules, each matching a different replica IP).
-spec resolve_host_refs(term(), map()) -> [term()].
resolve_host_refs({rule, Verdict, Opts}, Ctx) when is_map(Opts) ->
    IpMap = maps:get(ip_map, Ctx, #{}),
    %% First pass: resolve non-pod refs, collect pod refs separately
    {BaseOpts, PodRefs} = maps:fold(fun
        (iif, bridge, {Acc, Refs}) ->
            {Acc#{iif => maps:get(bridge, Ctx, <<"br0">>)}, Refs};
        (oif, bridge, {Acc, Refs}) ->
            {Acc#{oif => maps:get(bridge, Ctx, <<"br0">>)}, Refs};
        (oif, containers, {Acc, Refs}) ->
            {Acc#{oif => <<"vh_*">>}, Refs};
        (Dir, Name, {Acc, Refs}) when (Dir =:= iif orelse Dir =:= oif) andalso is_binary(Name) ->
            case binary:split(Name, <<".">>) of
                [PodName, CtName] ->
                    %% Pod-qualified: collect all replica IPs
                    Ips = find_all_replica_ips(PodName, CtName, IpMap),
                    IpKey = case Dir of iif -> saddr; oif -> daddr end,
                    case Ips of
                        [] -> {Acc#{Dir => Name}, Refs};
                        _ -> {Acc, [{IpKey, Ips} | Refs]}
                    end;
                _ ->
                    {Acc#{Dir => Name}, Refs}
            end;
        (K, V, {Acc, Refs}) -> {Acc#{K => V}, Refs}
    end, {#{}, []}, Opts),
    %% Second pass: expand pod refs into multiple rules via cartesian product
    case PodRefs of
        [] ->
            [{rule, Verdict, BaseOpts}];
        _ ->
            expand_pod_ref_rules(Verdict, BaseOpts, PodRefs)
    end;
resolve_host_refs(Rule, _Ctx) ->
    [Rule].

%% Find all IPs for a pod-qualified name across all replicas.
%% "worker" + "fn" matches "worker-0-fn", "worker-1-fn", etc.
-spec find_all_replica_ips(binary(), binary(), map()) -> [tuple()].
find_all_replica_ips(PodName, CtName, IpMap) ->
    Prefix = <<PodName/binary, "-">>,
    Suffix = <<"-", CtName/binary>>,
    PrefixLen = byte_size(Prefix),
    SuffixLen = byte_size(Suffix),
    maps:fold(fun(Name, Ip, Acc) ->
        NameLen = byte_size(Name),
        case NameLen > PrefixLen + SuffixLen of
            true ->
                case {binary:part(Name, 0, PrefixLen),
                      binary:part(Name, NameLen - SuffixLen, SuffixLen)} of
                    {Prefix, Suffix} -> [Ip | Acc];
                    _ -> Acc
                end;
            false ->
                case Name =:= <<PodName/binary, "-0-", CtName/binary>> of
                    true -> [Ip | Acc];
                    false -> Acc
                end
        end
    end, [], IpMap).

%% Expand pod refs into one rule per IP combination.
%% For a single pod ref (common case): one rule per IP.
%% For two pod refs (e.g. iif+oif both pod-qualified): cartesian product.
-spec expand_pod_ref_rules(atom(), map(), [{atom(), [tuple()]}]) -> [term()].
expand_pod_ref_rules(Verdict, BaseOpts, [{IpKey, Ips}]) ->
    [{rule, Verdict, BaseOpts#{IpKey => {element(1,Ip), element(2,Ip),
                                         element(3,Ip), element(4,Ip), 32}}}
     || Ip <- Ips];
expand_pod_ref_rules(Verdict, BaseOpts, [{K1, Ips1}, {K2, Ips2}]) ->
    [{rule, Verdict, BaseOpts#{K1 => {element(1,I1), element(2,I1),
                                      element(3,I1), element(4,I1), 32},
                                K2 => {element(1,I2), element(2,I2),
                                      element(3,I2), element(4,I2), 32}}}
     || I1 <- Ips1, I2 <- Ips2];
expand_pod_ref_rules(Verdict, BaseOpts, _) ->
    %% Fallback: more than 2 pod refs is unusual, just emit base
    [{rule, Verdict, BaseOpts}].

%%====================================================================
%% Internal -- Pod Forward Chains
%%====================================================================

%% Apply pod-internal forward chains after containers are spawned.
%% Resolves @ref (container name → veth) and adds rules to nft.
%% Returns [{PodChainName, [Veth, ...]}] for forward chain rebuild.
-spec apply_pod_forward_chains([map()], [map()], [{binary(), pid()}]) ->
    [{binary(), [binary()]}].
apply_pod_forward_chains(Pods, Zones, SpawnedPids) ->
    %% Build Name → veth map from spawned pids via inspect
    RunningMap = lists:foldl(fun({Name, Pid}, Acc) ->
        try erlkoenig:inspect(Pid) of
            #{net_info := #{host_veth := Veth, ip := Ip}} ->
                logger:info("erlkoenig_config: pod veth map: ~s → ~s ~p",
                            [Name, Veth, Ip]),
                Acc#{Name => #{host_veth => Veth, ip => Ip}};
            Other ->
                logger:warning("erlkoenig_config: inspect ~s: no net_info: ~p",
                               [Name, maps:keys(Other)]),
                Acc
        catch C:E ->
            logger:warning("erlkoenig_config: inspect ~s failed: ~p:~p", [Name, C, E]),
            Acc
        end
    end, #{}, SpawnedPids),

    lists:flatmap(fun(Pod) ->
        PodName = iolist_to_binary(maps:get(name, Pod, <<"?">>)),
        PodChains = maps:get(chains, Pod, []),
        case PodChains of
            [] -> [];
            _ ->
                ReplicaCounts = lists:filtermap(fun(Zone) ->
                    Deps = maps:get(deployments, Zone, []),
                    case lists:search(fun(#{pod := P}) ->
                        iolist_to_binary(P) =:= PodName
                    end, Deps) of
                        {value, #{replicas := N}} -> {true, N};
                        _ -> false
                    end
                end, Zones),
                Replicas = lists:sum(ReplicaCounts),
                ContainerNames = [iolist_to_binary(maps:get(name, C, <<"?">>))
                                  || C <- maps:get(containers, Pod, [])],
                apply_pod_chains_for_replicas(PodName, PodChains, ContainerNames,
                                              Replicas, RunningMap)
        end
    end, Pods).

-spec apply_pod_chains_for_replicas(binary(), [map()], [binary()],
                                     non_neg_integer(), map()) ->
    [{binary(), [binary()]}].
apply_pod_chains_for_replicas(PodName, PodChains, ContainerNames, Replicas, RunningMap) ->
    lists:filtermap(fun(ReplicaIdx) ->
        %% Build ref map for this replica: "frontend" → "vh_abc123"
        IdxBin = integer_to_binary(ReplicaIdx),
        RefMap = lists:foldl(fun(CtName, Acc) ->
            FullName = <<PodName/binary, "-", IdxBin/binary, "-", CtName/binary>>,
            case maps:find(FullName, RunningMap) of
                {ok, Info} when is_map(Info) ->
                    Acc#{CtName => Info};
                _ ->
                    logger:warning("erlkoenig_config: pod ~s ref ~s not found in running containers",
                                   [PodName, FullName]),
                    Acc
            end
        end, #{}, ContainerNames),

        %% Create a dedicated regular chain for this pod instance's forward rules.
        %% Then add a jump from the main forward chain BEFORE the per-container
        %% jump rules (which would otherwise intercept the traffic).
        PodChainName = iolist_to_binary([<<"pod_">>, PodName, <<"_">>, IdxBin]),

        HasChains = lists:any(fun(#{rules := R}) -> R =/= []; (_) -> false end, PodChains),
        %% Resolve @ref to IP and add rules directly to forward chain.
        %% Bridge traffic uses saddr/daddr because br_netfilter shows
        %% the bridge as iifname/oifname, not the container veths.
        _ = HasChains,
        _ = PodChainName,
        lists:foreach(fun(#{rules := Rules} = _Chain) ->
            ResolvedRules = lists:filtermap(fun(Rule) ->
                resolve_and_compile_rule(Rule, RefMap, PodName, <<"forward">>)
            end, Rules),
            case ResolvedRules of
                [] -> ok;
                _ ->
                    case nfnl_server:apply_msgs(erlkoenig_nft_srv, ResolvedRules) of
                        ok ->
                            logger:info("erlkoenig_config: pod ~s-~p: ~p forward rules",
                                        [PodName, ReplicaIdx, length(ResolvedRules)]);
                        {error, Reason} ->
                            logger:warning("erlkoenig_config: pod ~s-~p forward failed: ~p",
                                           [PodName, ReplicaIdx, Reason])
                    end
            end
        end, PodChains),
        false
    end, lists:seq(0, Replicas - 1)).

%% Resolve {ref, Name} in a rule's iif/oif to concrete veth names,
%% then compile to nft expression list targeting the pod chain.
-spec resolve_and_compile_rule(term(), map(), binary(), binary()) ->
    {true, fun()} | false.
resolve_and_compile_rule({rule, Verdict, Opts}, RefMap, PodName, ChainName) when is_map(Opts) ->
    Resolved = maps:fold(fun
        (iif, {ref, Name}, Acc) ->
            case resolve_ref_ip(Name, RefMap, PodName) of
                {ok, Ip} -> Acc#{saddr => {element(1,Ip), element(2,Ip), element(3,Ip), element(4,Ip), 32}};
                error -> Acc#{iif => <<"__unresolved__">>}
            end;
        (oif, {ref, Name}, Acc) ->
            case resolve_ref_ip(Name, RefMap, PodName) of
                {ok, Ip} -> Acc#{daddr => {element(1,Ip), element(2,Ip), element(3,Ip), element(4,Ip), 32}};
                error -> Acc#{oif => <<"__unresolved__">>}
            end;
        (K, V, Acc) -> Acc#{K => V}
    end, #{}, Opts),
    case has_unresolved(Resolved) of
        true ->
            logger:warning("erlkoenig_config: pod ~s: unresolved ref in ~p",
                           [PodName, Opts]),
            false;
        false ->
            try
                Compiled = erlkoenig_firewall_nft:compile_generic_rule(Verdict, Resolved),
                {true, nft_encode:rule_fun(inet, <<"erlkoenig">>,
                    ChainName, Compiled)}
            catch _:Err ->
                logger:warning("erlkoenig_config: pod ~s rule compile error: ~p",
                               [PodName, Err]),
                false
            end
    end;
resolve_and_compile_rule(Rule, _RefMap, PodName, ChainName) ->
    try
        Compiled = erlkoenig_firewall_nft:compile_rule(Rule),
        {true, nft_encode:rule_fun(inet, <<"erlkoenig">>,
            ChainName, Compiled)}
    catch _:Err ->
        logger:warning("erlkoenig_config: pod ~s rule compile error: ~p for ~p",
                       [PodName, Err, Rule]),
        false
    end.

-spec resolve_ref_ip(binary(), map(), binary()) -> {ok, tuple()} | error.
resolve_ref_ip(Name, RefMap, PodName) ->
    NameBin = iolist_to_binary(Name),
    case maps:find(NameBin, RefMap) of
        {ok, #{ip := Ip}} -> {ok, Ip};
        _ ->
            logger:warning("erlkoenig_config: pod ~s: @~s not found", [PodName, NameBin]),
            error
    end.

-spec has_unresolved(map()) -> boolean().
has_unresolved(Opts) ->
    lists:any(fun
        ({_, {ref, _}}) -> true;
        ({_, <<"__unresolved__">>}) -> true;
        (_) -> false
    end, maps:to_list(Opts)).

%%====================================================================
%% Internal -- Guard
%%====================================================================

-spec maybe_configure_guard(map()) -> ok.
maybe_configure_guard(#{guard := GuardConfig}) when is_map(GuardConfig) ->
    case erlang:whereis(erlkoenig_nft_ct_guard) of
        undefined ->
            logger:warning("erlkoenig_config: erlkoenig_nft_ct_guard not running, "
                           "guard config ignored"),
            ok;
        _Pid ->
            erlkoenig_nft_ct_guard:reconfigure(GuardConfig),
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

-spec build_spawn_opts(map()) -> map().
build_spawn_opts(Ct) ->
    Keys = [ip, ports, args, env, firewall, limits, seccomp,
            restart, name, files, zone, volumes, image_path, publish, stream],
    lists:foldl(fun(K, Acc) -> copy_if(K, Ct, Acc) end, #{}, Keys).

-spec copy_if(atom(), map(), map()) -> map().
copy_if(Key, From, To) ->
    case maps:find(Key, From) of
        {ok, Val} -> maps:put(Key, Val, To);
        error -> To
    end.

%%====================================================================
%% Internal -- Delta / Reload
%%====================================================================

-spec container_names(map()) -> [binary()].
container_names(Config) ->
    [iolist_to_binary(maps:get(name, C)) || C <- flatten_containers(Config)].

-spec stop_by_name(binary()) -> ok.
stop_by_name(Name) ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
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

%% For dnat_lb rules: create a named data map and inject map_name into rule opts.
%% Returns {UpdatedRule, [MapMessages]}.
-spec maybe_create_lb_map(term(), non_neg_integer(), binary()) ->
    {term(), [fun()]}.
maybe_create_lb_map({rule, dnat_lb, #{targets := Targets, dport := Port} = Opts}, Family, Table)
  when is_list(Targets), length(Targets) > 1 ->
    %% Generate deterministic map name from rule opts
    MapName = <<"__lb_", (integer_to_binary(erlang:phash2({Targets, Port})))/binary>>,
    MapId = erlang:phash2(MapName) band 16#FFFF,

    %% 1. Create the data map: mark (u32) → ipv4_addr
    %% key_type = mark (19) is a u32 that matches the hash output.
    %% key_type = 0 (untyped) is rejected by some kernel versions.
    CreateMap = fun(S) ->
        nft_set:add_data_map(Family, #{
            table => Table,
            name => MapName,
            key_type => 19,    %% mark = u32
            key_len => 4,      %% 4 bytes
            data_type => ipv4_addr
        }, MapId, S)
    end,

    %% 2. Add elements: {<<0:32>> → IP1, <<1:32>> → IP2, ...}
    Elements = lists:zip(
        [<<Idx:32/big>> || Idx <- lists:seq(0, length(Targets) - 1)],
        Targets
    ),
    AddElems = fun(S) ->
        nft_set_elem:add_data_map_elems(Family, Table, MapName, Elements, MapId, S)
    end,

    %% 3. Track map name for cleanup on next reload
    OldNames = persistent_term:get(erlkoenig_dsl_map_names_tmp, []),
    persistent_term:put(erlkoenig_dsl_map_names_tmp, [MapName | OldNames]),

    %% 4. Inject map_name and map_id for same-batch SET_ID correlation.
    %% Maps, elements, and rules are all in one atomic Netlink batch.
    Rule2 = {rule, dnat_lb, Opts#{map_name => MapName, map_id => MapId}},
    {Rule2, [CreateMap, AddElems]};

maybe_create_lb_map(Rule, _Family, _Table) ->
    {Rule, []}.

-spec force_stop_zone_containers(atom()) -> ok.
force_stop_zone_containers(ZoneName) ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch error:_ -> []
           end,
    lists:foreach(fun(Pid) ->
        try erlkoenig_ct:get_info(Pid) of
            #{zone := Z} when Z =:= ZoneName ->
                logger:info("erlkoenig_config: force stopping container in stale zone ~s", [ZoneName]),
                erlkoenig:stop(Pid);
            _ -> ok
        catch _:_ -> ok
        end
    end, Pids),
    ok.

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

ensure_config_tab() ->
    case ets:whereis(?CONFIG_TAB) of
        undefined ->
            ets:new(?CONFIG_TAB, [set, named_table, public]);
        _ ->
            ok
    end.

store_config(File, Config) ->
    ets:insert(?CONFIG_TAB, {File, Config}).

get_stored_config(File) ->
    case ets:whereis(?CONFIG_TAB) of
        undefined -> undefined;
        _ ->
            case ets:lookup(?CONFIG_TAB, File) of
                [{_, Config}] -> Config;
                [] -> undefined
            end
    end.
