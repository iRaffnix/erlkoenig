%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_config_flatten).
-moduledoc """
Expand a parsed DSL config into a flat list of container specs.

Pods + zones + replica counts collapse here into the per-instance
maps the rest of the runtime consumes. Per-zone IP counters are
allocated so containers from different pods that share a zone
don't collide — that's what `expand_container_replicas/4'
threads through.

The module is pure term-shuffling: no ETS, no processes. All
knowledge about the DSL's container-layout conventions lives
here.

`erlkoenig_config:flatten_containers/1' stays as the public
entry point and delegates here, so fuzz tests and ek tooling
keep using the well-known name.
""".

-export([
    flatten_containers/1,
    zone_subnet_prefix/1,
    expand_container_replicas/4
]).

%% Flatten pods+containers into a flat list. Each container gets its
%% own IP, a stable name `PodName-ReplicaIdx-CtName', and a zone atom.
%%
%% A per-zone IP counter is maintained so that containers sharing a zone
%% across different pods do not collide on IPs.
-spec flatten_containers(map()) -> [map()].
flatten_containers(Config) ->
    Pods = maps:get(pods, Config, []),
    Zones = maps:get(zones, Config, []),
    ZoneSubnets = maps:from_list(
        [{iolist_to_binary(maps:get(name, Z)),
          zone_subnet_prefix(Z)} || Z <- Zones]),

    %% Iterate pods → containers; expand replicas; one IP counter per zone.
    {AllContainers, _} = lists:foldl(fun(Pod, {Acc, ZoneIps}) ->
        PodBin = iolist_to_binary(maps:get(name, Pod)),
        PodContainers = maps:get(containers, Pod, []),
        {CtsFromPod, ZoneIps2} = lists:foldl(fun(Ct, {CtAcc, ZIps}) ->
            {NewCts, ZIps3} = expand_container_replicas(PodBin, Ct, ZoneSubnets, ZIps),
            {CtAcc ++ NewCts, ZIps3}
        end, {[], ZoneIps}, PodContainers),
        {Acc ++ CtsFromPod, ZoneIps2}
    end, {[], #{}}, Pods),

    %% Fallback: legacy flat `containers' key (no pods, no zones).
    case {AllContainers, maps:find(containers, Config)} of
        {[], {ok, Flat}} -> Flat;
        _                -> AllContainers
    end.

%% Extract {A, B, C} prefix from a zone's subnet (the /24 part).
-spec zone_subnet_prefix(map()) -> {byte(), byte(), byte()}.
zone_subnet_prefix(Zone) ->
    Net = maps:get(network, Zone, #{}),
    {A, B, C, _} = maps:get(subnet, Zone, maps:get(subnet, Net, {10, 0, 0, 0})),
    {A, B, C}.

%% Expand one container into N replicas, with per-zone IP counters.
-spec expand_container_replicas(binary(), map(), map(), map()) ->
    {[map()], map()}.
expand_container_replicas(PodName, Ct, ZoneSubnets, ZoneIps) ->
    CtName = maps:get(name, Ct, <<"unnamed">>),
    Replicas = maps:get(replicas, Ct, 1),
    ZoneBin = iolist_to_binary(maps:get(zone, Ct)),
    ZoneAtom = binary_to_atom(ZoneBin),
    Prefix = case maps:find(ZoneBin, ZoneSubnets) of
        {ok, P} -> P;
        error   -> {10, 0, 0}  %% fallback if zone not declared (shouldn't happen)
    end,
    IpStart = maps:get(ZoneBin, ZoneIps, 2),
    {Expanded, NextIp} = lists:foldl(fun(ReplicaIdx, {Acc, Ip}) ->
        {A, B, C} = Prefix,
        FullName = iolist_to_binary([PodName, "-",
                                     integer_to_binary(ReplicaIdx), "-",
                                     iolist_to_binary(CtName)]),
        Instance = Ct#{
            name => FullName,
            ip => {A, B, C, Ip},
            zone => ZoneAtom,
            pod => PodName,
            pod_instance => ReplicaIdx
        },
        {Acc ++ [Instance], Ip + 1}
    end, {[], IpStart}, lists:seq(0, Replicas - 1)),
    {Expanded, maps:put(ZoneBin, NextIp, ZoneIps)}.
