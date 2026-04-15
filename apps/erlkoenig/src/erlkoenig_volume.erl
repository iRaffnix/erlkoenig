%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_volume).
-moduledoc """
DSL-to-runtime volume resolver.

Expands a DSL volume declaration into runtime records carrying the
host-side UUID path. The actual metadata storage and directory
creation live in `erlkoenig_volume_store`; this module is the thin
glue between the container lifecycle (`erlkoenig_ct`) and the store.

Host paths resolve to:
  /var/lib/erlkoenig/volumes/<uuid>/
where `<uuid>` is stable for a given (container, persist) pair.

Persist-name validation (`[a-z0-9][a-z0-9_-]*`) stays here because
it's a pure input check, independent of the store.
""".

-export([validate_persist_name/1,
         resolve/4]).

%% Persist name: must start with [a-z0-9], followed by [a-z0-9_-]*
-spec validate_persist_name(binary()) -> ok | {error, invalid_persist_name}.
validate_persist_name(<<>>) ->
    {error, invalid_persist_name};
validate_persist_name(Name) when is_binary(Name) ->
    case re:run(Name, <<"^[a-z0-9][a-z0-9_-]*$">>) of
        {match, _} -> ok;
        nomatch -> {error, invalid_persist_name}
    end.

-doc """
Resolve DSL volume declarations into runtime representations. Each
volume is ensured in the metadata store, which creates the UUID
directory and chowns it to the container UID/GID on first call.

DslVolumes :: [#{container := binary(),
                 persist   := binary(),
                 read_only => boolean(),
                 opts      => binary(),
                 ephemeral => boolean()}]

Returned maps keep `container`, `persist`, `read_only`, `opts` (if
present), and add `host` (the UUID-based host path) plus `uuid` so
callers can reference the volume record without a second lookup.
""".
-spec resolve(binary(), [map()], non_neg_integer(), non_neg_integer()) ->
    {ok, [map()]} | {error, term()}.
resolve(_ContainerName, [], _Uid, _Gid) ->
    {ok, []};
resolve(ContainerName, DslVolumes, Uid, Gid) ->
    resolve_loop(ContainerName, DslVolumes, Uid, Gid, []).

resolve_loop(_ContainerName, [], _Uid, _Gid, Acc) ->
    {ok, lists:reverse(Acc)};
resolve_loop(ContainerName,
             [#{container := ContPath, persist := Persist} = Vol | Rest],
             Uid, Gid, Acc) ->
    case validate_persist_name(Persist) of
        ok ->
            Lifecycle = case maps:get(ephemeral, Vol, false) of
                true  -> ephemeral;
                false -> persistent
            end,
            Req0 = #{container => ContainerName,
                     persist   => Persist,
                     uid       => Uid,
                     gid       => Gid,
                     lifecycle => Lifecycle},
            %% Pass `quota` through to the store verbatim — parsing
            %% (e.g. "1G" → bytes) happens inside
            %% `erlkoenig_volume_store:parse_quota/1`, which also
            %% raises a clear `{invalid_quota, _}` on malformed input.
            Req = case maps:find(quota, Vol) of
                {ok, Quota} -> Req0#{quota => Quota};
                error       -> Req0
            end,
            case erlkoenig_volume_store:ensure(Req) of
                {ok, Record} ->
                    #{uuid := Uuid, host_path := HostPath} = Record,
                    ReadOnly = maps:get(read_only, Vol, false),
                    Resolved0 = #{uuid      => Uuid,
                                  host      => HostPath,
                                  container => ContPath,
                                  read_only => ReadOnly,
                                  persist   => Persist,
                                  lifecycle => Lifecycle},
                    Resolved1 = case maps:find(opts, Vol) of
                        {ok, OptsStr} -> Resolved0#{opts => OptsStr};
                        error         -> Resolved0
                    end,
                    Resolved = case maps:find(quota_bytes, Record) of
                        {ok, QB} -> Resolved1#{quota_bytes => QB};
                        error    -> Resolved1
                    end,
                    resolve_loop(ContainerName, Rest, Uid, Gid,
                                 [Resolved | Acc]);
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
    end.
