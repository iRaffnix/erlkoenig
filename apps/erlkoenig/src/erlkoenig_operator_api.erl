%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_operator_api).
-moduledoc """
Stable operator-facing API boundary.

The `ek` command-line tool and other operator adapters (AMQP
consumers, future HTTP/control-plane bindings) MUST call this module
instead of reaching into internal OTP modules directly. Functions
exported here are compatibility commitments: keep names, return
shapes, and field names stable across minor releases.

Internal modules still own the real state and implementation. This
module exists so those internals can be refactored without breaking
operator scripts.

## Return shape

Every wrapper returns one of:

- `ok`                       — for void side-effecting operations
- `{ok, Value}`              — where `Value` is documented per call
- `{error, error_map()}`     — see `erlkoenig_error:error_map/0`

Callers (notably `ek.escript`) use the error map's `code` field
(`EK_OPERATOR_*` etc.) to format messages and pick exit codes —
they do NOT pattern-match on raw tuples from internal modules.

## Adding a wrapper

1. Add the function with a `-spec` documenting the value shape.
2. Translate every internal return to the contract above using the
   `not_found_err/2`, `bad_arg_err/3`, `internal_err/2` helpers.
3. If a new EK code is needed, add it to
   `apps/erlkoenig/priv/error_catalog.term` so the CI gate stays
   green.
""".

-include("erlkoenig_error.hrl").

-export([
    %% Quarantine
    quarantine_list/0,
    quarantine_add/2,
    quarantine_remove/1,

    %% Admission
    admission_snapshot/0,

    %% Volumes
    volume_list/0,
    volume_list_by_container/1,
    volume_inspect/1,
    volume_destroy/1,
    volume_set_quota/2,
    volume_orphans/0,
    volume_gc_orphans/1,

    %% Node
    node_health/0,

    %% NFT
    nft_counters/0,
    firewall_status/0,
    firewall_events/1,
    firewall_events_since/3,

    %% Containers
    container_list/0,
    container_inspect/1,
    container_stop/1,

    %% Pods
    pod_list/0,
    pod_list_all/0
]).

-export_type([result/0, result/1, error_map/0]).

-type error_map() :: erlkoenig_error:error_map().
-type result()    :: ok | {error, error_map()}.
-type result(V)   :: {ok, V} | {error, error_map()}.

-type hash() :: binary().      % 64-char lowercase hex SHA-256

%%====================================================================
%% Quarantine
%%====================================================================

-doc """
Snapshot of the quarantine list.

Each entry is a map with at least:
- `hash`   :: 64-char lowercase hex binary
- `reason` :: term — original quarantine reason (`{crashloop, N, WindowMs}` etc.)
- `since`  :: integer — unix-ms of entry into quarantine
""".
-spec quarantine_list() -> result([#{hash := hash(),
                                     reason := term(),
                                     since := integer()}]).
quarantine_list() ->
    Raw = erlkoenig_quarantine:list(),
    {ok, [#{hash => H, reason => maps:get(reason, M),
            since => maps:get(since, M)}
          || {H, M} <- Raw]}.

-doc """
Manually quarantine a binary hash.

`Hash` must be a 64-character lowercase-hex SHA-256 binary. `Reason`
may be any term — operators typically pass a binary like
`<<"manual: investigation">>`.
""".
-spec quarantine_add(hash(), term()) -> result().
quarantine_add(Hash, Reason) ->
    case validate_hash(Hash) of
        ok ->
            ok = erlkoenig_quarantine:quarantine(Hash, Reason),
            ok;
        {error, _} = Err ->
            Err
    end.

-doc "Lift a hash from quarantine. Idempotent.".
-spec quarantine_remove(hash()) -> result().
quarantine_remove(Hash) ->
    case validate_hash(Hash) of
        ok ->
            ok = erlkoenig_quarantine:unquarantine(Hash),
            ok;
        {error, _} = Err ->
            Err
    end.

%%====================================================================
%% Admission
%%====================================================================

-doc """
Snapshot of the admission gate.

Returns `#{host_in_flight, zone_in_flight, queued}`. See
`erlkoenig_admission:snapshot/0` for field meaning.
""".
-spec admission_snapshot() ->
    result(#{host_in_flight := non_neg_integer(),
             zone_in_flight := #{binary() => non_neg_integer()},
             queued := non_neg_integer()}).
admission_snapshot() ->
    {ok, erlkoenig_admission:snapshot()}.

%%====================================================================
%% Volumes
%%====================================================================

-doc "All volume records on this node.".
-spec volume_list() -> result([erlkoenig_volume_store:volume()]).
volume_list() ->
    {ok, erlkoenig_volume_store:list()}.

-doc "Volume records owned by one container (by name binary).".
-spec volume_list_by_container(binary()) ->
    result([erlkoenig_volume_store:volume()]).
volume_list_by_container(Container) when is_binary(Container) ->
    {ok, erlkoenig_volume_store:list_by_container(Container)};
volume_list_by_container(Other) ->
    {error, bad_arg_err(container, Other, <<"binary container name">>)}.

-doc """
Look up a single volume by UUID or persist name.

Returns `{error, EK_OPERATOR_NOT_FOUND}` if no volume with that UUID
or persist name exists. If several containers use the same persist
name, the first current store record is returned; operators should
prefer UUIDs for mutating actions.
""".
-spec volume_inspect(binary()) -> result(erlkoenig_volume_store:volume()).
volume_inspect(IdOrPersist) when is_binary(IdOrPersist) ->
    case lists:search(fun(V) ->
                              maps:get(uuid, V) =:= IdOrPersist
                              orelse maps:get(persist, V) =:= IdOrPersist
                      end,
                      erlkoenig_volume_store:list()) of
        {value, Vol} -> {ok, Vol};
        false        -> {error, not_found_err(volume, IdOrPersist)}
    end;
volume_inspect(Other) ->
    {error, bad_arg_err(volume, Other, <<"binary uuid or persist name">>)}.

-doc """
Delete a volume by UUID. The on-disk directory is removed. Returns
`{error, EK_OPERATOR_NOT_FOUND}` if no volume with that UUID exists.
Other internal errors are surfaced as `EK_OPERATOR_INTERNAL`.
""".
-spec volume_destroy(binary()) -> result().
volume_destroy(Uuid) when is_binary(Uuid) ->
    case erlkoenig_volume_store:destroy(Uuid) of
        ok                  -> ok;
        {error, not_found}  -> {error, not_found_err(volume, Uuid)};
        {error, Reason}     -> {error, internal_err(volume_destroy, Reason)}
    end;
volume_destroy(Other) ->
    {error, bad_arg_err(uuid, Other, <<"binary uuid">>)}.

-doc """
Set or change the quota on a volume. Returns the updated volume
record.

`Spec` is either a non-negative integer of bytes, or a binary like
`<<"512M">>` / `<<"2G">>` (parsed by `erlkoenig_volume_store:parse_quota/1`).
""".
-spec volume_set_quota(binary(), non_neg_integer() | binary()) ->
    result(erlkoenig_volume_store:volume()).
volume_set_quota(Uuid, Spec) when is_binary(Uuid) ->
    case erlkoenig_volume_store:set_quota(Uuid, Spec) of
        {ok, Vol}          -> {ok, Vol};
        {error, not_found} -> {error, not_found_err(volume, Uuid)};
        {error, Reason}    -> {error, internal_err(volume_set_quota, Reason)}
    end;
volume_set_quota(Other, _Spec) ->
    {error, bad_arg_err(uuid, Other, <<"binary uuid">>)}.

-doc """
Disk-orphan volume UUIDs: directories under the volumes root whose
name starts with `ek_vol_` but for which no DETS metadata record
exists. These typically arise from interrupted `volume_destroy/1`
or crash-during-create paths.

This does NOT include volumes whose owner container is no longer
registered — those are still tracked metadata records and are
returned by `volume_list/0`. To find owner-orphans, diff
`volume_list/0` against `container_list/0` on the `container` field.
""".
-spec volume_orphans() -> result([binary()]).
volume_orphans() ->
    Root = erlkoenig_volume_store:volumes_root(),
    Known = sets:from_list([maps:get(uuid, V)
                            || V <- erlkoenig_volume_store:list()],
                           [{version, 2}]),
    case file:list_dir(binary_to_list(Root)) of
        {ok, Entries} ->
            Orphans = [list_to_binary(E) || E <- Entries,
                                            string:prefix(E, "ek_vol_") =/= nomatch,
                                            not sets:is_element(list_to_binary(E), Known)],
            {ok, Orphans};
        {error, Reason} ->
            {error, internal_err(volume_orphans, Reason)}
    end.

-doc """
Garbage-collect disk-orphan volume directories.

In `dry_run' mode, lists what would be deleted without touching the
filesystem. In `confirm' mode, deletes each orphan directory after
re-checking that the UUID is still not registered in the store
(race-safety against a volume getting created between the orphan
listing and the deletion).

Returns one map per orphan with stable string fields:

  - `uuid'   :: binary()  — the orphan UUID
  - `path'   :: binary()  — absolute filesystem path
  - `mode'   :: binary()  — `<<"dry_run">>' | `<<"confirm">>'
  - `status' :: binary()  — `<<"pending">>' | `<<"deleted">>' |
                            `<<"already_gone">>' | `<<"skipped">>' |
                            `<<"failed">>'
  - `reason' :: binary() | null — human-readable reason when
                                  `status' is `skipped' or `failed';
                                  `null' otherwise.

`vol orphans' remains a read-only discovery operation — store
metadata is never touched by gc-orphans.
""".
-spec volume_gc_orphans(dry_run | confirm) ->
    result([#{uuid   := binary(),
              path   := binary(),
              mode   := binary(),
              status := binary(),
              reason := binary() | null}]).
volume_gc_orphans(Mode) when Mode =:= dry_run; Mode =:= confirm ->
    Root = erlkoenig_volume_store:volumes_root(),
    case volume_orphans() of
        {ok, Uuids} ->
            Results = [gc_one_orphan(Root, U, Mode) || U <- Uuids],
            {ok, Results};
        {error, _} = Err ->
            Err
    end;
volume_gc_orphans(Other) ->
    {error, bad_arg_err(mode, Other, <<"dry_run | confirm">>)}.

gc_one_orphan(Root, Uuid, dry_run) ->
    Path = orphan_path(Root, Uuid),
    #{uuid => Uuid, path => Path,
      mode => <<"dry_run">>, status => <<"pending">>,
      reason => null};
gc_one_orphan(Root, Uuid, confirm) ->
    Path = orphan_path(Root, Uuid),
    %% Re-check that the UUID is still NOT registered in the store.
    %% Without this, an unfortunately timed `volume_create' between the
    %% orphan listing and the deletion could let us delete a freshly
    %% registered volume. Cost is one DETS scan per orphan, which is
    %% acceptable for an operator-driven gc run.
    Known = sets:from_list([maps:get(uuid, V)
                            || V <- erlkoenig_volume_store:list()],
                           [{version, 2}]),
    case sets:is_element(Uuid, Known) of
        true ->
            #{uuid => Uuid, path => Path,
              mode => <<"confirm">>, status => <<"skipped">>,
              reason => <<"became known after orphan snapshot">>};
        false ->
            case file:del_dir_r(binary_to_list(Path)) of
                ok ->
                    #{uuid => Uuid, path => Path,
                      mode => <<"confirm">>, status => <<"deleted">>,
                      reason => null};
                {error, enoent} ->
                    #{uuid => Uuid, path => Path,
                      mode => <<"confirm">>, status => <<"already_gone">>,
                      reason => null};
                {error, Reason} ->
                    #{uuid => Uuid, path => Path,
                      mode => <<"confirm">>, status => <<"failed">>,
                      reason => format_gc_reason(Reason)}
            end
    end.

orphan_path(Root, Uuid) ->
    iolist_to_binary([Root, "/", Uuid]).

format_gc_reason(R) when is_atom(R) ->
    atom_to_binary(R, utf8);
format_gc_reason(R) ->
    iolist_to_binary(io_lib:format("~p", [R])).

%%====================================================================
%% Node
%%====================================================================

-doc """
Coarse node health snapshot.

Returns `#{uptime_ms, sup_children}`. Used by `ek node health`.
Stable across minor releases — new keys may be added but existing
keys keep their meaning.
""".
-spec node_health() -> result(#{uptime_ms := non_neg_integer(),
                                sup_children := non_neg_integer()}).
node_health() ->
    {UptimeMs, _} = erlang:statistics(wall_clock),
    Children = try length(supervisor:which_children(erlkoenig_sup))
               catch _:_ -> 0
               end,
    {ok, #{uptime_ms => UptimeMs, sup_children => Children}}.

%%====================================================================
%% NFT
%%====================================================================

-doc """
Live nft counter snapshot.

Returns one row per configured firewall counter. Values come from the
running nft watcher state, which is fed by kernel counter reads.
""".
-spec nft_counters() -> result([map()]).
nft_counters() ->
    try erlkoenig_nft:list_counters() of
        Rows when is_list(Rows) ->
            {ok, Rows}
    catch
        Class:Reason ->
            {error, internal_err(nft_counters, {Class, Reason})}
    end.

-doc "Interactive firewall read-side status.".
-spec firewall_status() -> result(map()).
firewall_status() ->
    EventStats = case erlkoenig_firewall_events:stats() of
        {ok, S} -> S;
        {error, Reason} -> #{running => false, error => Reason}
    end,
    GuardStats = try erlkoenig_nft_ct_guard:stats()
                 catch _:_ -> #{running => false}
                 end,
    {ok, #{events => EventStats, guard => GuardStats}}.

-doc """
Newest canonical firewall events, oldest first.

The source is the node-local `erlkoenig_firewall_events` buffer. Each
event has at least `seq`, `id`, `ts_mono`, `ts_wall`, `source`,
`severity`, `kind`, `evidence`, and `labels`. Packet/threat events add
fields such as `src_ip`, `dst_ip`, `chain`, `dst_port`, and `reason`.
""".
-spec firewall_events(pos_integer()) -> result([map()]).
firewall_events(Limit) when is_integer(Limit), Limit > 0 ->
    case erlkoenig_firewall_events:recent(Limit) of
        {ok, Events} -> {ok, Events};
        {error, Reason} -> {error, internal_err(firewall_events, Reason)}
    end;
firewall_events(Other) ->
    {error, bad_arg_err(limit, Other, <<"positive integer">>)}.

-doc """
Canonical firewall events with `seq > Cursor`.

`TimeoutMs = 0` returns immediately. Positive values long-poll until a
new event arrives or the timeout expires.
""".
-spec firewall_events_since(non_neg_integer(), non_neg_integer(), pos_integer()) ->
    result(#{cursor := non_neg_integer(), events := [map()]}).
firewall_events_since(Cursor, TimeoutMs, Limit)
  when is_integer(Cursor), Cursor >= 0,
       is_integer(TimeoutMs), TimeoutMs >= 0,
       is_integer(Limit), Limit > 0 ->
    case erlkoenig_firewall_events:since(Cursor, TimeoutMs, Limit) of
        {ok, NewCursor, Events} ->
            {ok, #{cursor => NewCursor, events => Events}};
        {error, Reason} ->
            {error, internal_err(firewall_events_since, Reason)}
    end;
firewall_events_since(Cursor, TimeoutMs, Limit) ->
    {error, bad_arg_err(firewall_events_since,
                        #{cursor => Cursor, timeout_ms => TimeoutMs, limit => Limit},
                        <<"cursor >= 0, timeout_ms >= 0, limit > 0">>)}.

%%====================================================================
%% Containers
%%====================================================================

-doc """
List all running containers as `container_info()` maps.

Best-effort: containers that died between enumeration and inspect
are silently filtered by `erlkoenig:list/0`. Stopped/failed container
state machines remain available for post-mortem `container_inspect/1`,
but the list view is the live operator surface and only returns
`state := running`.
""".
-spec container_list() -> result([erlkoenig:container_info()]).
container_list() ->
    {ok, [Info || #{state := running} = Info <- erlkoenig:list()]}.

-doc """
Detailed info for one container, looked up by name or id.

Returns `{error, EK_OPERATOR_NOT_FOUND}` if no matching container is
registered.
""".
-spec container_inspect(binary()) -> result(erlkoenig:container_info()).
container_inspect(NameOrId) when is_binary(NameOrId) ->
    case find_container_pid(NameOrId) of
        {ok, Pid} ->
            case erlkoenig:inspect(Pid) of
                {error, not_found} -> {error, not_found_err(container, NameOrId)};
                Info when is_map(Info) -> {ok, Info}
            end;
        {error, not_found} ->
            {error, not_found_err(container, NameOrId)}
    end;
container_inspect(Other) ->
    {error, bad_arg_err(container, Other, <<"binary container name or id">>)}.

-doc """
Stop one container by name or id (SIGTERM, then SIGKILL after timeout).

Returns `{error, EK_OPERATOR_NOT_FOUND}` if the id is unknown, or
`EK_OPERATOR_INTERNAL` for runtime errors during the stop sequence.
""".
-spec container_stop(binary()) -> result().
container_stop(NameOrId) when is_binary(NameOrId) ->
    case find_container_pid(NameOrId) of
        {ok, Pid} ->
            case erlkoenig:stop(Pid) of
                ok              -> ok;
                {error, Reason} -> {error, internal_err(container_stop, Reason)}
            end;
        {error, not_found} ->
            {error, not_found_err(container, NameOrId)}
    end;
container_stop(Other) ->
    {error, bad_arg_err(container, Other, <<"binary container name or id">>)}.

%%====================================================================
%% Pods
%%====================================================================

-doc """
List active pods.

Returns one entry per pod supervisor whose direct children include
at least one container in a non-terminal state (anything other than
`stopped` or `failed`). Pods whose containers have all reached a
terminal state are filtered out — they are kept alive for
post-mortem inspection (`erlkoenig:inspect/1`) but should not appear
in operator dashboards as "running" pods.

Each entry is `#{name, pid, children}` where:
- `name`     :: binary — pod name from the supervisor's process label
- `pid`      :: pid    — the per-pod supervisor pid
- `children` :: non_neg_integer — count of containers in non-terminal state
""".
-spec pod_list() -> result([#{name := binary(),
                              pid := pid(),
                              children := non_neg_integer()}]).
pod_list() ->
    Children = try supervisor:which_children(erlkoenig_pod_sup_sup)
               catch _:_ -> []
               end,
    Rows = [pod_row(Pid) || {_Id, Pid, _Type, _Mod} <- Children, is_pid(Pid)],
    {ok, [R || R <- Rows, maps:get(children, R) > 0]}.

-doc """
All pod supervisors, including pods whose children are all terminal.

This is the backing API for `ek pod list --all`; the default
`pod_list/0` remains the active-operator view.
""".
-spec pod_list_all() -> result([#{name := binary(),
                                  pid := pid(),
                                  children := non_neg_integer()}]).
pod_list_all() ->
    Children = try supervisor:which_children(erlkoenig_pod_sup_sup)
               catch _:_ -> []
               end,
    {ok, [pod_row(Pid) || {_Id, Pid, _Type, _Mod} <- Children, is_pid(Pid)]}.

pod_row(Pid) ->
    Name = case proc_lib:get_label(Pid) of
        {erlkoenig_pod, N} -> N;
        _                  -> <<"?">>
    end,
    Active = try active_child_count(supervisor:which_children(Pid))
             catch _:_ -> 0
             end,
    #{name => Name, pid => Pid, children => Active}.

%% Count children that are still doing useful work. A container in
%% `stopped` or `failed` state is kept alive intentionally for
%% post-mortem inspection — it should not be counted as a live child
%% from an operator perspective.
active_child_count(Kids) ->
    lists:foldl(fun({_Id, Pid, _Type, _Mod}, Acc) when is_pid(Pid) ->
        case container_state(Pid) of
            stopped -> Acc;
            failed  -> Acc;
            _       -> Acc + 1
        end;
        (_, Acc) -> Acc
    end, 0, Kids).

container_state(Pid) ->
    try erlkoenig_ct:get_info(Pid) of
        #{state := S} -> S;
        _             -> unknown
    catch _:_ -> dead
    end.

find_container_pid(NameOrId) ->
    case erlkoenig:find_by_id(NameOrId) of
        {ok, Pid} ->
            {ok, Pid};
        {error, not_found} ->
            Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts_all)
                   catch error:_ -> []
                   end,
            find_container_pid_by_name(NameOrId, Pids)
    end.

find_container_pid_by_name(_Name, []) ->
    {error, not_found};
find_container_pid_by_name(Name, [Pid | Rest]) ->
    try erlkoenig:inspect(Pid) of
        #{name := Name} -> {ok, Pid};
        _               -> find_container_pid_by_name(Name, Rest)
    catch
        _:_ -> find_container_pid_by_name(Name, Rest)
    end.

%%====================================================================
%% Internal — error map construction
%%====================================================================

-spec validate_hash(term()) -> ok | {error, error_map()}.
validate_hash(H) when is_binary(H), byte_size(H) =:= 64 ->
    case is_lower_hex(H) of
        true  -> ok;
        false ->
            {error, bad_arg_err(hash, H,
                                <<"64-char lowercase hex SHA-256">>)}
    end;
validate_hash(Other) ->
    {error, bad_arg_err(hash, Other, <<"64-char lowercase hex SHA-256">>)}.

is_lower_hex(<<>>) -> true;
is_lower_hex(<<C, Rest/binary>>)
  when (C >= $0 andalso C =< $9)
       orelse (C >= $a andalso C =< $f) ->
    is_lower_hex(Rest);
is_lower_hex(_) -> false.

-spec not_found_err(atom(), term()) -> error_map().
not_found_err(Resource, Key) ->
    erlkoenig_error:make(operator, not_found,
                         "operator-API lookup found no matching resource",
                         #{resource => Resource, key => Key}).

-spec bad_arg_err(atom(), term(), binary()) -> error_map().
bad_arg_err(Argument, Value, Expected) ->
    erlkoenig_error:make(operator, bad_argument,
                         "operator-API call rejected on argument validation",
                         #{argument => Argument,
                           value => safe_value(Value),
                           expected => Expected}).

-spec internal_err(atom(), term()) -> error_map().
internal_err(Op, Raw) ->
    erlkoenig_error:make(operator, internal,
                         "operator-API wrapper received an unexpected return",
                         #{op => Op, raw => Raw}).

%% Truncate large/binary values so error maps stay compact in logs and
%% AMQP payloads. We only render the first 64 bytes for binaries.
safe_value(B) when is_binary(B), byte_size(B) > 64 ->
    <<H:64/binary, _/binary>> = B,
    <<H/binary, "...">>;
safe_value(V) -> V.
