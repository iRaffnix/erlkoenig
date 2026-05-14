%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_config_validate).
-moduledoc """
Pure validation of the parsed DSL term.

`validate_config/1' accepts both the unified zone-centric format
(`#{zones => [...]}') and the legacy flat container list
(`#{containers => [...]}'), so this layer happens once and the
rest of the runtime can assume a known-good shape.

This layer performs shape validation and static resource-budget checks
against the configured aggregate cgroup ceilings. It deliberately does
not call ETS or peer processes, so parse failures stay deterministic and
spawn-time gen_statem failures do not become the first feedback loop.
""".

-export([
    validate_config/1,
    validate_zones/1,
    validate_containers/1
]).

-spec validate_config(term()) -> ok | {error, term()}.
validate_config(Config) when is_map(Config) ->
    %% Unified format: #{images, firewall, zones, pods, steering, ct_guard, watch}
    %% Legacy format:  #{containers, watches, guard}
    %% Both are valid. Validate every present section instead of
    %% stopping at `zones': the newer pod-inline format carries its
    %% containers under `pods', and container-local nft errors must be
    %% caught before spawn, not later as opaque gen_statem failures.
    maybe
        ok ?= validate_zones_section(Config),
        ok ?= validate_legacy_containers_section(Config),
        ok ?= validate_pods_section(Config),
        ok ?= validate_resource_budget(Config),
        ok
    end;
validate_config(_) ->
    {error, invalid_config}.

validate_zones_section(Config) ->
    case maps:find(zones, Config) of
        {ok, Zones} when is_list(Zones) -> validate_zones(Zones);
        {ok, _}                         -> {error, {invalid_type, zones, expected_list}};
        error                           -> ok
    end.

validate_legacy_containers_section(Config) ->
    case maps:find(containers, Config) of
        {ok, Containers} when is_list(Containers) -> validate_containers(Containers);
        {ok, _}                                  -> {error, {invalid_type, containers, expected_list}};
        error                                    -> ok
    end.

validate_pods_section(Config) ->
    case maps:find(pods, Config) of
        {ok, Pods} when is_list(Pods) -> validate_pods(Pods);
        {ok, _}                       -> {error, {invalid_type, pods, expected_list}};
        error                         -> ok
    end.

validate_pods([]) -> ok;
validate_pods([#{name := PodName, containers := Cts} | Rest]) when is_list(Cts) ->
    maybe
        ok ?= validate_containers(Cts),
        ok ?= validate_pod_containers(iolist_to_binary(PodName), Cts),
        validate_pods(Rest)
    end;
validate_pods([#{name := _} | Rest]) ->
    validate_pods(Rest);
validate_pods([Bad | _]) ->
    {error, {invalid_pod, Bad}}.

validate_pod_containers(_PodName, []) -> ok;
validate_pod_containers(PodName, [Ct | Rest]) ->
    case validate_container_nft(PodName, Ct) of
        ok -> validate_pod_containers(PodName, Rest);
        Err -> Err
    end.

validate_container_nft(PodName, #{name := CtName} = Ct) ->
    Replicas = maps:get(replicas, Ct, 1),
    case maps:find(nft, Ct) of
        {ok, Nft} when is_map(Nft), is_integer(Replicas), Replicas > 0 ->
            validate_container_nft_replicas(PodName, iolist_to_binary(CtName),
                                            Nft, Replicas);
        {ok, _Other} ->
            {error, {invalid_container_nft, #{pod => PodName,
                                              container => iolist_to_binary(CtName),
                                              reason => invalid_nft_config}}};
        error ->
            ok
    end;
validate_container_nft(_PodName, _Ct) ->
    ok.

validate_container_nft_replicas(PodName, CtName, Nft, Replicas) ->
    case catch erlkoenig_nft_container:build_batch(Nft#{table => <<"validate">>}) of
        Bin when is_binary(Bin) ->
            ok;
        {'EXIT', Reason} ->
            {error, {invalid_container_nft,
                     #{container => replica_name(PodName, CtName, 0),
                       replicas => Replicas,
                       reason => Reason}}};
        Other ->
            {error, {invalid_container_nft,
                     #{container => replica_name(PodName, CtName, 0),
                       replicas => Replicas,
                       reason => Other}}}
    end.

replica_name(PodName, CtName, Idx) ->
    iolist_to_binary([PodName, "-", integer_to_binary(Idx), "-", CtName]).

-spec validate_zones(list()) -> ok | {error, term()}.
validate_zones([]) -> ok;
validate_zones([#{name := Name, deployments := _} | _]) ->
    %% Legacy zone-level `deployments' field (replicas attached to a
    %% zone) is refused post-6k. The current DSL puts each container
    %% in a pod with its own `zone:` and inline `replicas:'.
    {error, {legacy_zone_shape_refused,
             #{zone => Name, field => deployments,
               hint => <<"zones no longer carry `deployments`; declare "
                         "containers inside a pod with inline `zone:` "
                         "and `replicas:` per the current DSL">>}}};
validate_zones([#{name := Name, containers := _} | _]) ->
    %% Legacy zone-level `containers' field is refused post-6k. The
    %% current DSL routes each container through a pod; raw zone-
    %% level container lists were the pre-pod shape.
    {error, {legacy_zone_shape_refused,
             #{zone => Name, field => containers,
               hint => <<"zones no longer carry `containers`; declare "
                         "containers inside a pod with `zone:` set on "
                         "the container">>}}};
validate_zones([#{name := Name, bridge := _} | _]) ->
    {error, {legacy_zone_shape_refused,
             #{zone => Name, field => bridge,
               hint => <<"zones no longer carry `bridge`; declare "
                         "network => #{mode => ipvlan, parent => ...}">>}}};
validate_zones([#{name := Name, allows := _} | _]) ->
    {error, {legacy_zone_shape_refused,
             #{zone => Name, field => allows,
               hint => <<"zone-level `allows` belonged to the legacy "
                         "link-layer firewall path; use explicit "
                         "nft_tables rules">>}}};
validate_zones([#{name := _} | Rest]) ->
    %% Zone with no containers/deployments (isolated or chains-only).
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

%% =================================================================
%% Resource budget validation
%% =================================================================

-spec validate_resource_budget(map()) -> ok | {error, term()}.
validate_resource_budget(Config) ->
    Containers = all_declared_containers(Config),
    case resource_ceilings() of
        {ok, Ceilings} ->
            maybe
                ok ?= validate_container_limits(Containers, Ceilings),
                ok ?= validate_budget_sum(memory, Containers, Ceilings),
                ok ?= validate_budget_sum(pids, Containers, Ceilings),
                warn_unbounded_memory_limits(Containers, Ceilings),
                ok
            end;
        {error, _} = Err ->
            Err
    end.

-spec all_declared_containers(map()) -> [map()].
all_declared_containers(Config) ->
    Legacy = maps:get(containers, Config, []),
    PodContainers = [Ct || #{containers := Cts} <- maps:get(pods, Config, []),
                           Ct <- Cts],
    Legacy ++ PodContainers.

-spec resource_ceilings() -> {ok, map()} | {error, term()}.
resource_ceilings() ->
    try erlkoenig_cgroup:containers_config() of
        Cfg -> {ok, Cfg}
    catch
        Class:Reason ->
            {error, {invalid_resource_protection,
                     #{class => Class, reason => Reason}}}
    end.

-spec validate_container_limits([map()], map()) -> ok | {error, term()}.
validate_container_limits([], _Ceilings) ->
    ok;
validate_container_limits([Ct | Rest], Ceilings) ->
    case validate_one_container_limits(Ct, Ceilings) of
        ok -> validate_container_limits(Rest, Ceilings);
        Err -> Err
    end.

-spec validate_one_container_limits(map(), map()) -> ok | {error, term()}.
validate_one_container_limits(Ct, Ceilings) ->
    Name = container_name(Ct),
    case maps:get(limits, Ct, #{}) of
        Limits when is_map(Limits) ->
            maybe
                ok ?= validate_limit(memory, Name, maps:get(memory, Limits, undefined),
                                     maps:get(memory_max, Ceilings)),
                ok ?= validate_limit(pids, Name, maps:get(pids, Limits, undefined),
                                     maps:get(pids_max, Ceilings)),
                ok ?= validate_limit(cpu, Name, maps:get(cpu, Limits, undefined),
                                     100),
                ok
            end;
        Other ->
            {error, {invalid_container_limits,
                     #{container => Name, reason => invalid_limits,
                       value => Other}}}
    end.

-spec validate_limit(memory | pids | cpu, binary(), term(), pos_integer()) ->
    ok | {error, term()}.
validate_limit(_Kind, _Name, undefined, _Ceiling) ->
    ok;
validate_limit(cpu, _Name, Value, _Ceiling)
  when is_number(Value), Value > 0, Value =< 100 ->
    ok;
validate_limit(cpu, Name, Value, _Ceiling) ->
    invalid_limit(Name, cpu, Value, <<"number in 1..100; percent of one CPU core">>);
validate_limit(_Kind, _Name, Value, Ceiling)
  when is_integer(Value), Value > 0, Value =< Ceiling ->
    ok;
validate_limit(Kind, Name, Value, Ceiling)
  when is_integer(Value), Value > Ceiling ->
    {error, {container_limit_exceeds_ceiling,
             #{container => Name, limit => Kind, value => Value,
               ceiling => Ceiling}}};
validate_limit(Kind, Name, Value, _Ceiling) ->
    invalid_limit(Name, Kind, Value, <<"positive integer">>).

-spec validate_budget_sum(memory | pids, [map()], map()) -> ok | {error, term()}.
validate_budget_sum(Kind, Containers, Ceilings) ->
    CeilingKey = case Kind of
        memory -> memory_max;
        pids -> pids_max
    end,
    Ceiling = maps:get(CeilingKey, Ceilings),
    Total = lists:sum([declared_limit_total(Kind, Ct) || Ct <- Containers]),
    case Total =< Ceiling of
        true ->
            ok;
        false ->
            {error, {container_limit_total_exceeds_ceiling,
                     #{limit => Kind, total => Total, ceiling => Ceiling}}}
    end.

-spec declared_limit_total(memory | pids, map()) -> non_neg_integer().
declared_limit_total(Kind, Ct) ->
    Limits = maps:get(limits, Ct, #{}),
    case maps:get(Kind, Limits, undefined) of
        Value when is_integer(Value), Value > 0 ->
            Value * container_instance_count(Ct);
        _ ->
            0
    end.

-spec container_instance_count(map()) -> pos_integer().
container_instance_count(Ct) ->
    case maps:get(replicas, Ct, 1) of
        N when is_integer(N), N > 0 -> N;
        _ -> 1
    end.

-spec warn_unbounded_memory_limits([map()], map()) -> ok.
warn_unbounded_memory_limits([], _Ceilings) ->
    ok;
warn_unbounded_memory_limits(Containers, Ceilings) ->
    TotalInstances = lists:sum([container_instance_count(Ct) || Ct <- Containers]),
    Unbounded = lists:sum([unbounded_memory_instances(Ct) || Ct <- Containers]),
    case Unbounded of
        0 ->
            ok;
        _ ->
            Declared = lists:sum([declared_limit_total(memory, Ct) || Ct <- Containers]),
            Ceiling = maps:get(memory_max, Ceilings),
            Available = max(0, Ceiling - Declared),
            logger:warning(
              "resource budget: ~b/~b container instance(s) have no memory limit; "
              "declared_memory=~b aggregate_memory_max=~b unreserved_headroom=~b",
              [Unbounded, TotalInstances, Declared, Ceiling, Available]),
            ok
    end.

-spec unbounded_memory_instances(map()) -> non_neg_integer().
unbounded_memory_instances(Ct) ->
    Limits = maps:get(limits, Ct, #{}),
    case maps:get(memory, Limits, undefined) of
        Value when is_integer(Value), Value > 0 -> 0;
        _ -> container_instance_count(Ct)
    end.

-spec container_name(map()) -> binary().
container_name(Ct) ->
    case maps:get(name, Ct, <<"unknown">>) of
        Name when is_binary(Name) -> Name;
        Name when is_list(Name) -> iolist_to_binary(Name);
        Other -> iolist_to_binary(io_lib:format("~p", [Other]))
    end.

invalid_limit(Name, Kind, Value, Expected) ->
    {error, {invalid_container_limit,
             #{container => Name, limit => Kind, value => Value,
               expected => Expected}}}.
