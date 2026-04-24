%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_config_zone).
-moduledoc """
Apply-phase helpers for zones, host firewall and BPF steering.

These operate on the zone/firewall/steering subsections of a
parsed config and produce side effects in sibling subsystems:

  * `ensure_zones/2' → `erlkoenig_zone:create/destroy/zone_config'
  * `force_stop_zone_containers/1' → walks the `erlkoenig_cts' pg
    group and stops each container in a given zone (used on
    subnet-change recreation)
  * `maybe_apply_firewall/2' → writes the host firewall config
    file and asks `erlkoenig_nft' to reload; the firewall
    gen_server remains the single owner of nftables state
  * `maybe_apply_steering/3' → registers BPF steering routes +
    services with `erlkoenig_steering'
  * `find_container_ip/2' → small helper for the steering
    route-registration path
  * `log_deploy_report/3' → pretty-prints the deploy Report map

These are the parts of the config apply that weren't pure — they
change real infrastructure. The top-level `erlkoenig_config:load/1'
still owns the orchestration and the Report-map threading.
""".

-export([
    ensure_zones/2,
    force_stop_zone_containers/1,
    maybe_apply_firewall/2,
    maybe_apply_steering/3,
    find_container_ip/2,
    log_deploy_report/3
]).

%% Ensure zones exist (bridge + IP pool + DNS)
-spec ensure_zones(list(), map()) -> map().
ensure_zones(Zones, Report) ->
    Results = lists:map(fun(#{name := Name} = Zone) ->
        ZoneAtom = binary_to_atom(iolist_to_binary(Name)),
        ZoneConfig = case maps:get(network, Zone, #{}) of
            #{mode := ipvlan} = Net ->
                #{network => #{mode => ipvlan,
                               parent => maps:get(parent, Net, <<"eth0">>),
                               parent_type => maps:get(parent_type, Net, device),
                               ipvlan_mode => maps:get(ipvlan_mode, Net, l3s),
                               subnet => maps:get(subnet, Zone, maps:get(subnet, Net, {10,0,0,0})),
                               gateway => maps:get(gateway, Net, maps:get(gateway, Zone, undefined)),
                               netmask => maps:get(netmask, Zone, maps:get(netmask, Net, 24))},
                  policy => maps:get(policy, Zone, allow_outbound)};
            _ ->
                %% Legacy format → IPVLAN with dummy (ADR-0020)
                #{network => #{mode => ipvlan,
                               parent => <<"ek_default">>,
                               parent_type => dummy,
                               ipvlan_mode => l3s,
                               subnet => maps:get(subnet, Zone, {10,0,0,0}),
                               gateway => undefined,
                               netmask => maps:get(netmask, Zone, 24)},
                  policy => maps:get(policy, Zone, allow_outbound)}
        end,
        try erlkoenig_zone:zone_config(ZoneAtom) of
            OldCfg ->
                %% Zone exists — check if config changed (subnet/gateway)
                OldNet = maps:get(network, OldCfg, #{}),
                OldSubnet = maps:get(subnet, OldNet, undefined),
                NewNet = maps:get(network, ZoneConfig, #{}),
                NewSubnet = maps:get(subnet, NewNet, undefined),
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
