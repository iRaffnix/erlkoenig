%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_volume).
-moduledoc """
Volume resolution + FUSE rootfs build / mount / cleanup.

Split out of `erlkoenig_ct' so the volume and FUSE subsystems
have one home. Callers:

  * `creating(enter, _)` → `resolve_volumes/1' turns the DSL's
    raw volume maps into records with UUID-backed host paths.
  * `namespace_ready(enter, _)` → `erlkoenig_ct_cgroup:do_container_setup/1'
    calls `maybe_setup_rootfs/1' right after the cgroup is set
    up and before network setup, because the rootfs manifest
    has to exist before the C runtime is told to `GO'.
  * `stopped(enter, _)` / `failed(enter, _)' → `cleanup_fuse/1'.

The FUSE helpers are `-dialyzer({no_missing_calls, _})'-friendly:
`erlkoenig_fuse_manifest' and `erlkoenig_fuse_mount_sup' are
runtime-optional siblings so their calls are wrapped in
`try … catch error:undef' to keep the node bootable without them.
""".

-include("erlkoenig_ct_state.hrl").

-dialyzer({no_missing_calls, [save_manifest/2, start_fuse_mount/3,
                               cleanup_fuse/1]}).

-export([
    resolve_volumes/1,
    maybe_setup_rootfs/1,
    cleanup_fuse/1
]).

%% -- Volume resolution -------------------------------------------

-spec resolve_volumes(#ct_data{}) -> #ct_data{}.
resolve_volumes(#ct_data{volumes = []} = Data) ->
    Data;
resolve_volumes(#ct_data{volumes = DslVolumes, name = Name, id = Id,
                         uid = Uid, gid = Gid} = Data) ->
    ContainerName = case Name of
        undefined -> Id;
        N -> N
    end,
    %% erlkoenig_volume_store:ensure/1 (called from resolve/4) handles
    %% directory creation + chown under the volumes root. We don't
    %% need the separate ensure_volume_dir step any more.
    case erlkoenig_volume:resolve(ContainerName, DslVolumes, Uid, Gid) of
        {ok, Resolved} ->
            Data#ct_data{volumes = Resolved};
        {error, Reason} ->
            logger:error("container ~s: volume resolution failed: ~p",
                         [Id, Reason]),
            Data
    end.

%% --- FUSE rootfs setup / cleanup ---

-doc "Build and mount FUSE rootfs if a rootfs config is present.".
%% The rootfs config lives in extra_opts (put there by the DSL compiler).
%% If no rootfs config → legacy mode (no FUSE), returns Data unchanged.
-spec maybe_setup_rootfs(#ct_data{}) -> {ok, #ct_data{}} | {error, term()}.
maybe_setup_rootfs(Data) ->
    case maps:get(rootfs, Data#ct_data.extra_opts, undefined) of
        undefined ->
            %% No rootfs spec → legacy mode (no FUSE)
            {ok, Data};
        _RootfsSpec ->
            setup_fuse_rootfs(Data)
    end.

-spec setup_fuse_rootfs(#ct_data{}) -> {ok, #ct_data{}} | {error, term()}.
setup_fuse_rootfs(Data) ->
    ContainerId = Data#ct_data.id,
    ExtraOpts = Data#ct_data.extra_opts,
    RootfsConfig = #{
        rootfs => maps:get(rootfs, ExtraOpts, #{}),
        binary => Data#ct_data.binary_path,
        seccomp => maps:get(rootfs_seccomp, ExtraOpts, undefined)
    },
    case find_store_pid() of
        undefined ->
            logger:warning("erlkoenig_fuse_store not available, "
                           "skipping FUSE rootfs for ~s", [ContainerId]),
            {ok, Data};
        Pid ->
            BuildOpts = case Data#ct_data.name of
                undefined -> #{};
                Name      -> #{artifact_name => Name}
            end,
            maybe
                {ok, #{manifest := Manifest,
                       tmpfs_mounts := TmpfsMounts}} ?=
                    case erlkoenig_rootfs_builder:build(RootfsConfig, Pid, BuildOpts) of
                        {ok, _} = Ok -> Ok;
                        {error, Reason1} ->
                            logger:error("Failed to build rootfs for ~s: ~p",
                                         [ContainerId, Reason1]),
                            {error, {rootfs_build_failed, Reason1}}
                    end,
                %% Save manifest
                ManifestPath = manifest_path(ContainerId),
                save_manifest(Manifest, ManifestPath),
                %% Start FUSE mount
                MountPath = fuse_mount_path(ContainerId),
                _ = filelib:ensure_path(MountPath),
                {ok, _MountPid} ?=
                    case start_fuse_mount(ContainerId, Manifest, MountPath) of
                        {ok, _} = Ok2 -> Ok2;
                        {error, Reason2} ->
                            logger:error("Failed to mount FUSE for ~s: ~p",
                                         [ContainerId, Reason2]),
                            {error, {fuse_mount_failed, Reason2}}
                    end,
                MountBin = unicode:characters_to_binary(MountPath),
                logger:info("FUSE rootfs mounted for ~s at ~s",
                            [ContainerId, MountPath]),
                {ok, Data#ct_data{
                    fuse_mount = MountBin,
                    tmpfs_mounts = TmpfsMounts
                }}
            else
                {error, _} = Err -> Err
            end
    end.

-spec find_store_pid() -> pid() | undefined.
find_store_pid() ->
    whereis(erlkoenig_fuse_store).

-spec manifest_path(binary()) -> string().
manifest_path(ContainerId) ->
    Dir = application:get_env(erlkoenig, manifest_dir,
                              "/var/lib/erlkoenig/manifests"),
    _ = filelib:ensure_dir(filename:join(Dir, "x")),
    filename:join(Dir, binary_to_list(ContainerId) ++ ".manifest").

-spec fuse_mount_path(binary()) -> string().
fuse_mount_path(ContainerId) ->
    Dir = application:get_env(erlkoenig, fuse_mount_dir,
                              "/run/erlkoenig/mounts"),
    _ = filelib:ensure_dir(filename:join(Dir, "x")),
    filename:join(Dir, binary_to_list(ContainerId)).

-spec save_manifest(term(), string()) -> ok.
save_manifest(Manifest, Path) ->
    try
        erlkoenig_fuse_manifest:save(Manifest, Path)
    catch
        error:undef ->
            logger:warning("erlkoenig_fuse_manifest not available, "
                           "skipping manifest save"),
            ok;
        _:Reason ->
            logger:warning("manifest save failed: ~p", [Reason]),
            ok
    end.

-spec start_fuse_mount(binary(), term(), string()) ->
    {ok, pid()} | {error, term()}.
start_fuse_mount(ContainerId, Manifest, MountPath) ->
    try
        erlkoenig_fuse_mount_sup:start_mount(
            ContainerId, Manifest,
            #{mountpoint => MountPath})
    catch
        error:undef ->
            {error, fuse_mount_sup_not_available};
        _:Reason ->
            {error, Reason}
    end.

-doc "Cleanup FUSE mount when container stops or fails.".
-spec cleanup_fuse(#ct_data{}) -> ok.
cleanup_fuse(#ct_data{fuse_mount = undefined}) ->
    ok;
cleanup_fuse(#ct_data{id = ContainerId}) ->
    %% Two silent layers before hardening: `_ =` discarded an
    %% {error, _} return, and `catch _:_ -> ok' swallowed crashes.
    %% A stuck EBUSY unmount would leak the mountpoint directory
    %% with zero operator signal. Surface both branches now — keep
    %% the fire-and-forget semantics, but log.
    try erlkoenig_fuse_mount_sup:stop_mount(ContainerId) of
        ok -> ok;
        {error, Reason} ->
            logger:warning("container ~s: fuse unmount failed: ~p "
                           "(mountpoint may leak)", [ContainerId, Reason]),
            ok
    catch
        Class:Err ->
            logger:warning("container ~s: fuse unmount crashed: ~p:~p",
                           [ContainerId, Class, Err]),
            ok
    end.
