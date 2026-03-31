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

-doc "Load a config file and spawn all containers.".
-spec load(file:filename()) -> {ok, [{binary(), pid()}]} | {error, term()}.
load(TermFile) ->
    maybe
        {ok, Config} ?= parse(TermFile),
        ok ?= validate_config(Config),
        _ = ensure_config_tab(),
        Result = apply_config(Config),
        store_config(TermFile, Config),
        Result
    else
        {error, _} = Err -> Err
    end.

-doc "Reload a config file. Stops removed containers, starts new ones.".
-spec reload(file:filename()) -> {ok, [{binary(), pid()}]} | {error, term()}.
reload(TermFile) ->
    maybe
        {ok, NewConfig} ?= parse(TermFile),
        ok ?= validate_config(NewConfig),
        _ = ensure_config_tab(),
        OldConfig = get_stored_config(TermFile),
        apply_delta(OldConfig, NewConfig),
        store_config(TermFile, NewConfig),
        {ok, []}
    else
        {error, _} = Err -> Err
    end.

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

-spec apply_config(map()) -> {ok, [{binary(), pid()}]}.
apply_config(Config) ->
    Report = #{},

    %% 1. Validate images
    Images = maps:get(images, Config, #{}),
    Report1 = validate_images(Images, Report),

    %% 2. Create/update zones (bridges before firewall)
    Zones = maps:get(zones, Config, []),
    Report2 = ensure_zones(Zones, Report1),

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

    %% 6. Reconcile containers
    AllContainers = flatten_containers(Config),
    Results = lists:filtermap(fun spawn_container/1, AllContainers),

    %% 7. Apply steering
    Report4 = maybe_apply_steering(Config, AllContainers, Report3),

    %% 8. Log report
    log_deploy_report(Report4, length(Results), length(AllContainers)),

    {ok, Results}.

%% Flatten containers from zones or legacy format
-spec flatten_containers(map()) -> [map()].
flatten_containers(#{zones := Zones}) when is_list(Zones) ->
    lists:flatmap(fun(#{containers := Cts} = Zone) ->
        ZoneName = maps:get(name, Zone, <<"default">>),
        [Ct#{zone => binary_to_atom(iolist_to_binary(ZoneName))} || Ct <- Cts];
       (_) -> []
    end, Zones);
flatten_containers(#{containers := Containers}) ->
    Containers;
flatten_containers(_) ->
    [].

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

-spec apply_delta(map() | undefined, map()) -> ok.
apply_delta(undefined, NewConfig) ->
    _ = apply_config(NewConfig),
    ok;
apply_delta(OldConfig, NewConfig) ->
    OldNames = container_names(OldConfig),
    NewNames = container_names(NewConfig),

    %% Stop removed containers
    Removed = OldNames -- NewNames,
    lists:foreach(fun(Name) ->
        stop_by_name(Name)
    end, Removed),

    %% Start added containers
    Added = NewNames -- OldNames,
    NewContainers = maps:get(containers, NewConfig, []),
    lists:foreach(fun(Ct) ->
        Name = iolist_to_binary(maps:get(name, Ct)),
        case lists:member(Name, Added) of
            true -> spawn_container(Ct);
            false -> ok
        end
    end, NewContainers),

    ok.

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
