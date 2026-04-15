%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_volume_store).
-moduledoc """
Metadata store for persistent container volumes.

Each volume has a UUID-based on-disk identity
(`/var/lib/erlkoenig/volumes/<uuid>/`) decoupled from the container
name. Metadata (owner container, persist name, UID/GID, lifecycle)
lives in a DETS index at `/var/lib/erlkoenig/volumes/.index.dets`.

## Why UUID-based?

Binding storage paths to container names (as the first-cut design did)
couples data to naming:

- Container rename orphans the whole storage tree.
- Replica renames create drift.
- Cleanup by container-name is fragile.

A stable UUID per (container, persist) pair, with metadata recording
the logical name, lets us rename containers, migrate replicas, and
enforce cleanup policies — without touching the data directory.

## Lifecycle

- `persistent` (default): survives container destroy. Explicit
  `destroy/1` required to delete.
- `ephemeral`: destroyed with the container. `cleanup_ephemeral/1`
  is called from the container state machine on stop/fail.

## Optional by-name symlinks

For operator debuggability, `/var/lib/erlkoenig/volumes/by-name/<container>/<persist>`
can symlink to the UUID directory. These are advisory — the metadata
store is authoritative.
""".

-behaviour(gen_server).

-export([start_link/0,
         ensure/1,
         find/2,
         list/0,
         list_by_container/1,
         destroy/1,
         cleanup_ephemeral/1,
         set_quota/2,
         volumes_root/0,
         parse_quota/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(TABLE, erlkoenig_volumes).
-define(DEFAULT_VOLUMES_ROOT, <<"/var/lib/erlkoenig/volumes">>).

%% Project IDs we allocate live in this range. Starts at 10_000 to
%% leave low IDs for operator-defined projects (matches util-linux
%% `/etc/projects` conventions). Wraps at 2**31-1 (XFS u32 signed).
-define(PROJECT_ID_MIN, 10_000).
-define(PROJECT_ID_MAX, 16#7fffffff).

%% Volumes root is read from the `erlkoenig` app env at start_link/0
%% (key: `volumes_root`). Default matches what operators set up via
%% patterns/volume-backing-setup.md. Tests override it to a tmpdir.

-type lifecycle() :: persistent | ephemeral.

-type volume() :: #{
    uuid        := binary(),
    container   := binary(),
    persist     := binary(),
    host_path   := binary(),
    uid         := non_neg_integer(),
    gid         := non_neg_integer(),
    lifecycle   := lifecycle(),
    created_at  := integer(),
    %% Quota fields are only present when a quota was requested.
    %% `quota_bytes` is the hard limit in bytes; `project_id` is the
    %% XFS project id bound to the directory tree. 0 quota = unset.
    quota_bytes => non_neg_integer(),
    project_id  => non_neg_integer()
}.

-export_type([volume/0, lifecycle/0]).

%%====================================================================
%% Public API
%%====================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec volumes_root() -> binary().
volumes_root() ->
    case application:get_env(erlkoenig, volumes_root) of
        {ok, Path} when is_binary(Path) -> Path;
        {ok, Path} when is_list(Path)   -> iolist_to_binary(Path);
        undefined                        -> ?DEFAULT_VOLUMES_ROOT
    end.

-spec index_file() -> string().
index_file() ->
    binary_to_list(iolist_to_binary([volumes_root(), <<"/.index.dets">>])).

-spec by_name_dir() -> string().
by_name_dir() ->
    binary_to_list(iolist_to_binary([volumes_root(), <<"/by-name">>])).

-doc """
Ensure a volume exists for the given container+persist. Creates a
new UUID-based entry if absent, returns the existing entry otherwise.

`uid` and `gid` are applied to the on-disk directory on first
creation — subsequent calls don't re-chown (operator may have
adjusted permissions).

`lifecycle` only takes effect at creation time. An existing volume
keeps its original lifecycle — switching persistent↔ephemeral on
the fly would be surprising.
""".
-spec ensure(#{container := binary(), persist := binary(),
               uid := non_neg_integer(), gid := non_neg_integer(),
               lifecycle => lifecycle()}) ->
    {ok, volume()} | {error, term()}.
ensure(#{container := _, persist := _,
         uid := _, gid := _} = Req) ->
    gen_server:call(?SERVER, {ensure, Req}).

-doc "Lookup by (container, persist). Not an error if absent.".
-spec find(binary(), binary()) -> {ok, volume()} | not_found.
find(Container, Persist)
  when is_binary(Container), is_binary(Persist) ->
    gen_server:call(?SERVER, {find, Container, Persist}).

-doc "All volume records.".
-spec list() -> [volume()].
list() -> gen_server:call(?SERVER, list).

-doc "All volume records for one container.".
-spec list_by_container(binary()) -> [volume()].
list_by_container(Container) when is_binary(Container) ->
    gen_server:call(?SERVER, {list_by_container, Container}).

-doc """
Destroy one volume by UUID: removes the metadata entry, the on-disk
directory (`rm -rf`), and any by-name symlink.
""".
-spec destroy(binary()) -> ok | {error, term()}.
destroy(Uuid) when is_binary(Uuid) ->
    gen_server:call(?SERVER, {destroy, Uuid}).

-doc """
Destroy all ephemeral volumes belonging to a container. Called from
the container state machine on stop/fail. Persistent volumes are
untouched — they survive container destroy by definition.

Returns the UUIDs that were destroyed.
""".
-spec cleanup_ephemeral(binary()) -> {ok, [binary()]} | {error, term()}.
cleanup_ephemeral(Container) when is_binary(Container) ->
    gen_server:call(?SERVER, {cleanup_ephemeral, Container}).

-doc """
Apply an XFS project quota to an existing volume. Allocates a project
ID if the volume doesn't have one yet, binds the project ID to the
volume directory tree, and sets a hard byte limit.

`Bytes = 0` removes the quota (clears the limit but keeps the
project-ID association so subsequent raises don't need to re-bind).

Best-effort: if `xfs_quota` is missing, fails silently at the
subprocess layer (warning logged, metadata still updated so the
value shows up in events and future retries). Callers treat
`{ok, _}` as "metadata recorded" and don't assume kernel-level
enforcement.
""".
-spec set_quota(binary(), non_neg_integer() | binary()) ->
    {ok, volume()} | {error, term()}.
set_quota(Uuid, Spec) when is_binary(Uuid) ->
    gen_server:call(?SERVER, {set_quota, Uuid, Spec}).

-doc """
Parse a human-readable quota specification into bytes.

Accepts:
- integer bytes (`1024` → 1024)
- decimal+suffix binaries (`<<"1G">>`, `<<"500M">>`, `<<"2T">>`)
  where the suffix is one of K/M/G/T/P, binary multipliers (1024)
- empty string or `0` → `0` (no quota)

Raises `{invalid_quota, Input}` on anything else so callers get a
clear error at config-load instead of a silent zero.
""".
-spec parse_quota(non_neg_integer() | binary() | string()) ->
    non_neg_integer().
parse_quota(0) -> 0;
parse_quota(N) when is_integer(N), N > 0 -> N;
parse_quota(<<>>) -> 0;
parse_quota(Bin) when is_binary(Bin) ->
    case re:run(Bin, <<"^(\\d+)\\s*([KMGTP]?)B?$">>,
                [caseless, {capture, all_but_first, binary}]) of
        {match, [N, Suffix]} ->
            Num = binary_to_integer(N),
            Num * multiplier(Suffix);
        nomatch ->
            erlang:error({invalid_quota, Bin})
    end;
parse_quota(Input) when is_list(Input) ->
    parse_quota(iolist_to_binary(Input));
parse_quota(Input) ->
    erlang:error({invalid_quota, Input}).

multiplier(<<>>)    -> 1;
multiplier(<<"K">>) -> 1024;
multiplier(<<"k">>) -> 1024;
multiplier(<<"M">>) -> 1024 * 1024;
multiplier(<<"m">>) -> 1024 * 1024;
multiplier(<<"G">>) -> 1024 * 1024 * 1024;
multiplier(<<"g">>) -> 1024 * 1024 * 1024;
multiplier(<<"T">>) -> 1024 * 1024 * 1024 * 1024;
multiplier(<<"t">>) -> 1024 * 1024 * 1024 * 1024;
multiplier(<<"P">>) -> 1024 * 1024 * 1024 * 1024 * 1024;
multiplier(<<"p">>) -> 1024 * 1024 * 1024 * 1024 * 1024.

%%====================================================================
%% gen_server
%%====================================================================

init([]) ->
    IndexFile = index_file(),
    ok = filelib:ensure_dir(IndexFile),
    case dets:open_file(?TABLE, [{file, IndexFile}, {type, set},
                                  {keypos, 1}, {auto_save, 5000}]) of
        {ok, ?TABLE} ->
            {ok, #{}};
        {error, Reason} ->
            {stop, {dets_open_failed, Reason}}
    end.

handle_call({ensure, Req}, _From, State) ->
    {reply, do_ensure(Req), State};

handle_call({find, Container, Persist}, _From, State) ->
    {reply, do_find(Container, Persist), State};

handle_call(list, _From, State) ->
    Records = dets:foldl(fun({_Uuid, V}, Acc) -> [V | Acc] end, [], ?TABLE),
    {reply, Records, State};

handle_call({list_by_container, Container}, _From, State) ->
    Records = dets:foldl(
        fun({_Uuid, #{container := C} = V}, Acc) when C =:= Container ->
              [V | Acc];
           (_, Acc) -> Acc
        end, [], ?TABLE),
    {reply, Records, State};

handle_call({destroy, Uuid}, _From, State) ->
    {reply, do_destroy(Uuid), State};

handle_call({cleanup_ephemeral, Container}, _From, State) ->
    {reply, do_cleanup_ephemeral(Container), State};

handle_call({set_quota, Uuid, Spec}, _From, State) ->
    {reply, do_set_quota(Uuid, Spec), State}.

handle_cast(_, State) -> {noreply, State}.
handle_info(_, State) -> {noreply, State}.

terminate(_Reason, _State) ->
    _ = dets:close(?TABLE),
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Internal
%%====================================================================

-spec do_ensure(map()) -> {ok, volume()} | {error, term()}.
do_ensure(#{container := Container, persist := Persist,
            uid := Uid, gid := Gid} = Req) ->
    case do_find(Container, Persist) of
        {ok, Existing} ->
            %% Volume exists. If the caller asks for a quota that
            %% differs from the stored one, apply the change — this
            %% lets operators raise/lower limits via a config reload.
            case maybe_reconcile_quota(Existing, Req) of
                {ok, Updated} -> {ok, Updated};
                {error, _} = E -> E
            end;
        not_found ->
            Uuid = new_uuid(),
            HostPath = uuid_path(Uuid),
            Lifecycle = maps:get(lifecycle, Req, persistent),
            QuotaBytes = parse_quota(maps:get(quota, Req, 0)),
            BaseRecord = #{uuid       => Uuid,
                           container  => Container,
                           persist    => Persist,
                           host_path  => HostPath,
                           uid        => Uid,
                           gid        => Gid,
                           lifecycle  => Lifecycle,
                           created_at => erlang:system_time(second)},
            case ensure_dir(HostPath, Uid, Gid) of
                ok ->
                    Record = apply_quota_on_create(BaseRecord, QuotaBytes),
                    ok = dets:insert(?TABLE, {Uuid, Record}),
                    _ = maybe_ensure_by_name_symlink(Container, Persist, Uuid),
                    {ok, Record};
                {error, _} = Err ->
                    Err
            end
    end.

-spec maybe_reconcile_quota(volume(), map()) ->
    {ok, volume()} | {error, term()}.
maybe_reconcile_quota(Existing, Req) ->
    case maps:find(quota, Req) of
        error ->
            %% Caller didn't specify a quota — leave whatever's there.
            {ok, Existing};
        {ok, Spec} ->
            Requested = parse_quota(Spec),
            Current = maps:get(quota_bytes, Existing, 0),
            case Requested =:= Current of
                true  -> {ok, Existing};
                false -> do_set_quota(maps:get(uuid, Existing), Requested)
            end
    end.

-spec apply_quota_on_create(volume(), non_neg_integer()) -> volume().
apply_quota_on_create(Record, 0) ->
    Record;
apply_quota_on_create(Record, Bytes) ->
    %% Allocate a project ID now, best-effort-bind it to the dir.
    ProjectId = next_project_id(),
    HostPath = maps:get(host_path, Record),
    _ = xfs_project_bind(HostPath, ProjectId),
    _ = xfs_project_limit(ProjectId, Bytes),
    Record#{project_id => ProjectId, quota_bytes => Bytes}.

-spec do_find(binary(), binary()) -> {ok, volume()} | not_found.
do_find(Container, Persist) ->
    Hits = dets:foldl(
        fun({_Uuid, #{container := C, persist := P} = V}, Acc)
             when C =:= Container, P =:= Persist -> [V | Acc];
           (_, Acc) -> Acc
        end, [], ?TABLE),
    case Hits of
        [V | _] -> {ok, V};
        []      -> not_found
    end.

-spec do_destroy(binary()) -> ok | {error, term()}.
do_destroy(Uuid) ->
    case dets:lookup(?TABLE, Uuid) of
        [{Uuid, #{host_path := HostPath,
                  container := Container,
                  persist := Persist} = V}] ->
            %% Clear any quota binding first so the project ID doesn't
            %% keep accounting the dir after the data goes away.
            _ = case maps:get(project_id, V, 0) of
                    0 -> ok;
                    Pid ->
                        _ = xfs_project_limit(Pid, 0),
                        _ = xfs_project_unbind(HostPath, Pid),
                        ok
                end,
            %% rm -rf is destructive but scoped to the volume root;
            %% the directory name is a UUID we generated, so no
            %% user-controlled path traversal is possible.
            _ = rm_rf(HostPath),
            _ = maybe_remove_by_name_symlink(Container, Persist),
            ok = dets:delete(?TABLE, Uuid),
            ok;
        [] ->
            {error, not_found}
    end.

-spec do_set_quota(binary(), non_neg_integer() | binary()) ->
    {ok, volume()} | {error, term()}.
do_set_quota(Uuid, Spec) ->
    case dets:lookup(?TABLE, Uuid) of
        [{Uuid, V}] ->
            Bytes = parse_quota(Spec),
            HostPath = maps:get(host_path, V),
            {Pid, V1} =
                case maps:get(project_id, V, 0) of
                    0 when Bytes > 0 ->
                        %% First quota for this volume — allocate + bind.
                        Allocated = next_project_id(),
                        _ = xfs_project_bind(HostPath, Allocated),
                        {Allocated, V#{project_id => Allocated}};
                    Existing ->
                        {Existing, V}
                end,
            _ = case {Pid, Bytes} of
                    {0, _} ->
                        %% No project id and Bytes == 0 → nothing to do.
                        ok;
                    {_, _} ->
                        xfs_project_limit(Pid, Bytes)
                end,
            Updated = case Bytes of
                0 -> maps:remove(quota_bytes, V1);
                _ -> V1#{quota_bytes => Bytes}
            end,
            ok = dets:insert(?TABLE, {Uuid, Updated}),
            {ok, Updated};
        [] ->
            {error, not_found}
    end.

-spec do_cleanup_ephemeral(binary()) -> {ok, [binary()]}.
do_cleanup_ephemeral(Container) ->
    Targets = dets:foldl(
        fun({_Uuid, #{container := C, lifecycle := ephemeral,
                      uuid := U}}, Acc) when C =:= Container -> [U | Acc];
           (_, Acc) -> Acc
        end, [], ?TABLE),
    Destroyed = [U || U <- Targets, do_destroy(U) =:= ok],
    {ok, Destroyed}.

%%====================================================================
%% Helpers
%%====================================================================

-spec new_uuid() -> binary().
new_uuid() ->
    %% 8 bytes random → 16 hex chars. ~1.8e19 address space, collision
    %% risk at <10^6 volumes is negligible. `ek_vol_` prefix makes the
    %% directory name recognisable when grepping mounts or ls-ing the
    %% volumes root.
    Hex = binary:encode_hex(crypto:strong_rand_bytes(8)),
    <<"ek_vol_", (string:lowercase(Hex))/binary>>.

-spec uuid_path(binary()) -> binary().
uuid_path(Uuid) ->
    iolist_to_binary([volumes_root(), $/, Uuid]).

-spec ensure_dir(binary(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
ensure_dir(HostPath, Uid, Gid) ->
    Path = binary_to_list(HostPath),
    case file:make_dir(Path) of
        ok ->
            chown_and_mode(Path, Uid, Gid);
        {error, eexist} ->
            %% Directory already exists — leave permissions alone,
            %% operator may have customised them.
            ok;
        {error, _} = Err ->
            Err
    end.

-spec chown_and_mode(string(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
chown_and_mode(Path, Uid, Gid) ->
    %% 0750: container UID + erlkoenig-service group can read; others
    %% are shut out. A bind-mount into the container's rootfs is all
    %% the container ever sees anyway.
    _ = file:change_mode(Path, 8#0750),
    case file:change_owner(Path, Uid, Gid) of
        ok -> ok;
        {error, Reason} ->
            %% Non-fatal: operator may be running without CAP_CHOWN
            %% (dev setup). Log, return ok so the volume is still
            %% usable. If writes fail later, that's caught elsewhere.
            logger:warning("volume_store: chown ~s to ~p:~p failed: ~p",
                          [Path, Uid, Gid, Reason]),
            ok
    end.

-spec maybe_ensure_by_name_symlink(binary(), binary(), binary()) ->
    ok | {error, term()}.
maybe_ensure_by_name_symlink(Container, Persist, Uuid) ->
    ByNameDir = filename:join([by_name_dir(), binary_to_list(Container)]),
    _ = filelib:ensure_dir(ByNameDir ++ "/"),
    _ = file:make_dir(ByNameDir),
    LinkPath = filename:join(ByNameDir, binary_to_list(Persist)),
    %% Relative target so moving the volumes root doesn't break links.
    Target = filename:join(["..", "..", binary_to_list(Uuid)]),
    case file:make_symlink(Target, LinkPath) of
        ok -> ok;
        {error, eexist} -> ok;
        {error, _} = Err -> Err
    end.

-spec maybe_remove_by_name_symlink(binary(), binary()) -> ok.
maybe_remove_by_name_symlink(Container, Persist) ->
    ByNameDir = filename:join([by_name_dir(), binary_to_list(Container)]),
    LinkPath = filename:join(ByNameDir, binary_to_list(Persist)),
    _ = file:delete(LinkPath),
    %% If the container dir is empty, remove it too. Best-effort.
    _ = file:del_dir(ByNameDir),
    ok.

-spec rm_rf(binary()) -> ok | {error, term()}.
rm_rf(Path) when is_binary(Path) ->
    %% file:del_dir_r/1 was added in OTP 23; we target OTP 28.
    file:del_dir_r(binary_to_list(Path)).

%%====================================================================
%% XFS project quota — best-effort subprocess wrappers.
%%
%% These shell out to `xfs_quota` because no portable
%% `quotactl(Q_XSETQLIM)` wrapper exists in Erlang/OTP. The command is
%% idempotent at the kernel layer and the subprocess cost only happens
%% on volume create/destroy, not on any hot path.
%%
%% In dev setups (non-XFS /tmp, missing `xfs_quota` binary, running
%% without CAP_SYS_ADMIN) the calls fail gracefully — the metadata
%% still records the requested limit so a later move to a real XFS
%% mount picks it up on reconciliation. That matches the ownership
%% best-effort pattern used elsewhere in this module.
%%====================================================================

-spec next_project_id() -> non_neg_integer().
next_project_id() ->
    %% Pick max(stored) + 1, floored at PROJECT_ID_MIN. Single-process
    %% access (this gen_server) makes the scan-then-assign race-free.
    Max = dets:foldl(
        fun({_Uuid, V}, Acc) ->
              max(Acc, maps:get(project_id, V, 0))
        end, 0, ?TABLE),
    Candidate = max(?PROJECT_ID_MIN, Max + 1),
    case Candidate > ?PROJECT_ID_MAX of
        true  -> erlang:error(project_id_exhausted);
        false -> Candidate
    end.

-spec xfs_project_bind(binary(), non_neg_integer()) -> ok.
xfs_project_bind(Dir, ProjectId) ->
    %% `project -s -p <dir> <id>` tags the directory tree with the
    %% project ID. Must run after the dir is created but before files
    %% are written if we want full accounting accuracy.
    Cmd = io_lib:format("xfs_quota -x -c 'project -s -p ~s ~p' ~s 2>&1",
                        [binary_to_list(Dir), ProjectId,
                         binary_to_list(volumes_root())]),
    run_xfs_quota(Cmd, {project_bind, Dir, ProjectId}).

-spec xfs_project_unbind(binary(), non_neg_integer()) -> ok.
xfs_project_unbind(Dir, ProjectId) ->
    Cmd = io_lib:format("xfs_quota -x -c 'project -C -p ~s ~p' ~s 2>&1",
                        [binary_to_list(Dir), ProjectId,
                         binary_to_list(volumes_root())]),
    run_xfs_quota(Cmd, {project_unbind, Dir, ProjectId}).

-spec xfs_project_limit(non_neg_integer(), non_neg_integer()) -> ok.
xfs_project_limit(ProjectId, Bytes) ->
    %% `limit -p bhard=<bytes> <id>` sets the hard byte limit. Setting
    %% bhard=0 clears the limit.
    Cmd = io_lib:format(
        "xfs_quota -x -c 'limit -p bhard=~p ~p' ~s 2>&1",
        [Bytes, ProjectId, binary_to_list(volumes_root())]),
    run_xfs_quota(Cmd, {project_limit, ProjectId, Bytes}).

-spec run_xfs_quota(iolist(), term()) -> ok.
run_xfs_quota(Cmd, Tag) ->
    %% Skip the subprocess entirely when the volumes root is
    %% obviously not a real XFS mount (e.g. a `/tmp` eunit fixture).
    %% Saves ~50 ms of fork-exec per call and sidesteps the
    %% accumulated subprocess-spawn overhead that destabilises
    %% unrelated test modules when many volumes are created back-to-back.
    case xfs_quota_available() of
        false -> ok;
        true ->
            Flat = lists:flatten(Cmd),
            Output = os:cmd(Flat),
            case string:trim(Output) of
                "" -> ok;
                Msg ->
                    logger:warning("volume_store: xfs_quota ~p failed: ~s",
                                   [Tag, Msg]),
                    ok
            end
    end.

%% True only when the volumes root looks like a real host FS *and*
%% `xfs_quota` is on PATH. Test fixtures (paths under `/tmp/`) always
%% return false, which makes quota calls no-ops in eunit.
-spec xfs_quota_available() -> boolean().
xfs_quota_available() ->
    case get({?MODULE, xfs_quota_available}) of
        undefined ->
            Answer = do_check_xfs_quota(),
            _ = put({?MODULE, xfs_quota_available}, Answer),
            Answer;
        Cached -> Cached
    end.

-spec do_check_xfs_quota() -> boolean().
do_check_xfs_quota() ->
    Root = binary_to_list(volumes_root()),
    case string:prefix(Root, "/tmp/") of
        nomatch ->
            case os:find_executable("xfs_quota") of
                false -> false;
                _Path -> true
            end;
        _ ->
            false
    end.
