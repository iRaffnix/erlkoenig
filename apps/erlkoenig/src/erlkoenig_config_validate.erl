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

Only syntactic checks live here — no app-env lookups, no ETS,
no peer-process calls. That keeps the tests easy and the seam
between parse and apply clean.
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
