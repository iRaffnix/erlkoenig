%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0

-module(erlkoenig_volume).
-moduledoc """
Persistent volume management for Erlkoenig containers.

Handles persist-name validation, host-path resolution, directory creation,
and DSL-to-runtime volume resolution.

Host paths are derived from persist names:
  /var/lib/erlkoenig/volumes/<container>/<persist>/

Persist names must match: [a-z0-9][a-z0-9_-]*
""".

-export([validate_persist_name/1,
         resolve_host_path/2,
         ensure_volume_dir/1,
         resolve/2]).

-define(VOLUME_BASE, "/var/lib/erlkoenig/volumes").

%% Persist name: must start with [a-z0-9], followed by [a-z0-9_-]*
-spec validate_persist_name(binary()) -> ok | {error, invalid_persist_name}.
validate_persist_name(<<>>) ->
    {error, invalid_persist_name};
validate_persist_name(Name) when is_binary(Name) ->
    case re:run(Name, <<"^[a-z0-9][a-z0-9_-]*$">>) of
        {match, _} -> ok;
        nomatch -> {error, invalid_persist_name}
    end.

%% Resolve the host path for a given container + persist name.
-spec resolve_host_path(binary(), binary()) -> binary().
resolve_host_path(ContainerName, PersistName) ->
    iolist_to_binary([<<?VOLUME_BASE>>, $/, ContainerName, $/, PersistName]).

%% Ensure the volume directory exists on the host.
%% Creates the directory if new. Does NOT change ownership of existing dirs.
-spec ensure_volume_dir(binary()) -> ok | {error, term()}.
ensure_volume_dir(HostPath) when is_binary(HostPath) ->
    Path = binary_to_list(HostPath),
    ok = filelib:ensure_dir(Path ++ "/"),
    case filelib:is_dir(Path) of
        true ->
            ok;
        false ->
            case file:make_dir(Path) of
                ok -> ok;
                {error, eexist} -> ok;
                {error, Reason} -> {error, Reason}
            end
    end.

%% Resolve DSL volume declarations into runtime representations.
%%
%% DslVolumes :: [#{container := binary(), persist := binary(),
%%                   read_only => boolean()}]
%% Returns resolved volumes with host paths filled in.
-spec resolve(binary(), [map()]) ->
    {ok, [#{host := binary(), container := binary(),
            read_only := boolean(), persist := binary()}]}
    | {error, term()}.
resolve(_ContainerName, []) ->
    {ok, []};
resolve(ContainerName, DslVolumes) ->
    resolve_loop(ContainerName, DslVolumes, []).

resolve_loop(_ContainerName, [], Acc) ->
    {ok, lists:reverse(Acc)};
resolve_loop(ContainerName, [#{container := ContPath, persist := Persist} = Vol | Rest], Acc) ->
    ReadOnly = maps:get(read_only, Vol, false),
    case validate_persist_name(Persist) of
        ok ->
            HostPath = resolve_host_path(ContainerName, Persist),
            Resolved = #{
                host => HostPath,
                container => ContPath,
                read_only => ReadOnly,
                persist => Persist
            },
            resolve_loop(ContainerName, Rest, [Resolved | Acc]);
        {error, _} = Err ->
            Err
    end.
