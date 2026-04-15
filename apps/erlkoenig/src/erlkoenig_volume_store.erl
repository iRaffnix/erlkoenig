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
         volumes_root/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(TABLE, erlkoenig_volumes).
-define(DEFAULT_VOLUMES_ROOT, <<"/var/lib/erlkoenig/volumes">>).

%% Volumes root is read from the `erlkoenig` app env at start_link/0
%% (key: `volumes_root`). Default matches what operators set up via
%% patterns/volume-backing-setup.md. Tests override it to a tmpdir.

-type lifecycle() :: persistent | ephemeral.

-type volume() :: #{
    uuid       := binary(),
    container  := binary(),
    persist    := binary(),
    host_path  := binary(),
    uid        := non_neg_integer(),
    gid        := non_neg_integer(),
    lifecycle  := lifecycle(),
    created_at := integer()
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
    {reply, do_cleanup_ephemeral(Container), State}.

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
            {ok, Existing};
        not_found ->
            Uuid = new_uuid(),
            HostPath = uuid_path(Uuid),
            Lifecycle = maps:get(lifecycle, Req, persistent),
            Record = #{uuid       => Uuid,
                       container  => Container,
                       persist    => Persist,
                       host_path  => HostPath,
                       uid        => Uid,
                       gid        => Gid,
                       lifecycle  => Lifecycle,
                       created_at => erlang:system_time(second)},
            case ensure_dir(HostPath, Uid, Gid) of
                ok ->
                    ok = dets:insert(?TABLE, {Uuid, Record}),
                    _ = maybe_ensure_by_name_symlink(Container, Persist, Uuid),
                    {ok, Record};
                {error, _} = Err ->
                    Err
            end
    end.

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
                  persist := Persist}}] ->
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
