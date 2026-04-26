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
