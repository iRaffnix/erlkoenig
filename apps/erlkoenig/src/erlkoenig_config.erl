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
        Result
    else
        {error, _} = Err -> Err
    end.

-doc "Reload a config file. Alias for load/1 (both are idempotent).".
-spec reload(file:filename()) -> {ok, [{binary(), pid()}]} | {error, term()}.
reload(TermFile) ->
    load(TermFile).

%%====================================================================
%% Internal -- Validation
%%====================================================================

-spec validate_config(map()) -> ok | {error, term()}.
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

    %% 2. Create/update zones (bridges before firewall)
    Zones = maps:get(zones, Config, []),
    Report2 = ensure_zones(Zones, Report1),

    %% 2b. Rebuild nft table with zone-aware bridges
    %% This ensures masquerade rules reference the correct zone bridges
    %% instead of the default erlkoenig_br0.
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
            erlkoenig_firewall_nft:setup_table(ZoneNftConfigs),
            %% Remove stale default bridge if zone bridges are used.
            %% The default erlkoenig_br0 may conflict (same subnet).
            _ = os:cmd("ip link delete erlkoenig_br0 2>/dev/null"),
            ok
    end,

    %% 2c. Apply zone network policy
    lists:foreach(fun(#{allows := _, bridge := Bridge} = Zone) ->
        BridgeBin = iolist_to_binary(Bridge),
        erlkoenig_firewall_nft:apply_zone_allows(Zone, BridgeBin);
       (#{chains := Chains} = Zone) when is_list(Chains), Chains =/= [] ->
        %% New format: compile zone chains to nft forward rules
        apply_zone_chains(Zone);
       (_) -> ok
    end, Zones),

    %% 3. Apply host firewall
    Report3 = maybe_apply_firewall(Config, Report2),

    %% 4. Apply guard
    maybe_configure_guard(Config),

    %% 5. Apply watches
    Watches = maps:get(watches, Config, maps:get(watch, Config, [])),
    WatchList = if is_list(Watches) -> Watches;
                   is_map(Watches) -> [Watches];
                   true -> []
                end,
    lists:foreach(fun start_watch/1, WatchList),

    %% 6. Reconcile containers (delta)
    AllContainers = flatten_containers(Config),
    DeclaredNames = [iolist_to_binary(maps:get(name, C)) || C <- AllContainers],
    RunningNames = container_names_from_old(OldConfig),

    %% Stop removed containers
    ToStop = RunningNames -- DeclaredNames,
    lists:foreach(fun(Name) ->
        logger:info("erlkoenig_config: stopping removed container ~s", [Name]),
        stop_by_name(Name)
    end, ToStop),

    %% Start new containers (not already running)
    ToStart = DeclaredNames -- RunningNames,
    Results = lists:filtermap(fun(Ct) ->
        Name = iolist_to_binary(maps:get(name, Ct)),
        case lists:member(Name, ToStart) of
            true -> spawn_container(Ct);
            false ->
                logger:debug("erlkoenig_config: ~s already running, keeping", [Name]),
                false
        end
    end, AllContainers),

    %% 6b. Apply pod-internal forward chains (after spawn, need veth names)
    timer:sleep(1500),
    logger:info("erlkoenig_config: spawned ~p containers for pod forward: ~p",
                [length(Results), [N || {N, _} <- Results]]),
    Pods = maps:get(pods, Config, []),
    apply_pod_forward_chains(Pods, maps:get(zones, Config, []), Results),

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
        try
            case erlkoenig_zone:zone_config(ZoneAtom) of
                _ -> {Name, already_exists}
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
-spec apply_zone_chains(map()) -> ok.
apply_zone_chains(#{chains := Chains} = Zone) ->
    ZoneName = maps:get(name, Zone, <<"?">>),
    lists:foreach(fun(#{name := _ChainName, rules := Rules}) ->
        RuleMsgs = lists:filtermap(fun(Rule) ->
            try
                Compiled = erlkoenig_firewall_nft:compile_rule(Rule),
                {true, nft_encode:rule_fun(inet, <<"erlkoenig_ct">>,
                    <<"forward">>, Compiled)}
            catch _:Err ->
                logger:warning("erlkoenig_config: zone ~s rule compile error: ~p for ~p",
                               [ZoneName, Err, Rule]),
                false
            end
        end, Rules),
        case RuleMsgs of
            [] -> ok;
            _ ->
                case nfnl_server:apply_msgs(erlkoenig_nft_srv, RuleMsgs) of
                    ok ->
                        logger:info("erlkoenig_config: zone ~s: ~p forward rules applied",
                                    [ZoneName, length(RuleMsgs)]);
                    {error, Reason} ->
                        logger:warning("erlkoenig_config: zone ~s chain apply failed: ~p",
                                       [ZoneName, Reason])
                end
        end
    end, Chains);
apply_zone_chains(_) ->
    ok.

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
                {true, nft_encode:rule_fun(inet, <<"erlkoenig_ct">>,
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
        {true, nft_encode:rule_fun(inet, <<"erlkoenig_ct">>,
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
    Table    = iolist_to_binary(maps:get(table, Watch, <<"erlkoenig_ct">>)),
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
            restart, name, files, zone, volumes, image_path],
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
