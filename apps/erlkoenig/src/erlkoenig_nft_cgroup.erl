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

-module(erlkoenig_nft_cgroup).
-moduledoc """
Resolve cgroupv2 IDs from systemd service names.

On systemd hosts, each service runs in its own cgroup under
/sys/fs/cgroup/system.slice/<service>.service/

The cgroup ID is read from the cgroup.id file in that directory.
This ID can be used with nft_rules:cgroup_accept/1 and
cgroup_drop/1 to write per-service firewall rules.

Example:
    {ok, Id} = erlkoenig_nft_cgroup:service_id("nginx.service").
    %% Id = 1234
    Rule = nft_rules:cgroup_accept(Id).
""".

-export([service_id/1, service_id/2]).

-define(CGROUP_BASE, "/sys/fs/cgroup").

-doc """
Resolve the cgroupv2 ID for a systemd service.

Looks up /sys/fs/cgroup/system.slice/<Service>/cgroup.id.
Service can be a string or binary, with or without the .service suffix.

Returns {ok, Id} or {error, Reason}.

Example:
    {ok, Id} = erlkoenig_nft_cgroup:service_id("nginx").
    {ok, Id} = erlkoenig_nft_cgroup:service_id("nginx.service").
    {ok, Id} = erlkoenig_nft_cgroup:service_id(<<"postgresql">>).
""".
-spec service_id(string() | binary()) ->
    {ok, non_neg_integer()}
    | {error,
        {empty_cgroup_id, binary() | string()}
        | {bad_cgroup_id, string(), binary() | string()}
        | {read_failed, atom(), binary() | string()}
        | {service_not_found, string(), binary() | string()}}.
service_id(Service) ->
    service_id(Service, "system.slice").

-doc """
Resolve the cgroupv2 ID for a systemd service in a specific slice.

Example:
    {ok, Id} = erlkoenig_nft_cgroup:service_id("myapp", "user.slice").
""".
-spec service_id(string() | binary(), string() | binary()) ->
    {ok, non_neg_integer()}
    | {error,
        {empty_cgroup_id, binary() | string()}
        | {bad_cgroup_id, string(), binary() | string()}
        | {read_failed, atom(), binary() | string()}
        | {service_not_found, string(), binary() | string()}}.
service_id(Service, Slice) ->
    ServiceStr = ensure_service_suffix(to_list(Service)),
    SliceStr = to_list(Slice),
    Path = filename:join([?CGROUP_BASE, SliceStr, ServiceStr, "cgroup.id"]),
    case file:read_file(Path) of
        {ok, Bin} ->
            case string:trim(binary_to_list(Bin)) of
                "" ->
                    {error, {empty_cgroup_id, Path}};
                IdStr ->
                    try
                        {ok, list_to_integer(IdStr)}
                    catch
                        error:badarg -> {error, {bad_cgroup_id, IdStr, Path}}
                    end
            end;
        {error, enoent} ->
            {error, {service_not_found, ServiceStr, Path}};
        {error, Reason} ->
            {error, {read_failed, Reason, Path}}
    end.

%% --- Internal ---

-spec ensure_service_suffix(string()) -> string().
ensure_service_suffix(Name) ->
    case lists:suffix(".service", Name) of
        true -> Name;
        false -> Name ++ ".service"
    end.

-spec to_list(string() | binary()) -> string().
to_list(S) when is_list(S) -> S;
to_list(B) when is_binary(B) -> binary_to_list(B).
