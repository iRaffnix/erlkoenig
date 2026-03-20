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

-module(erlkoenig_rootfs_builder).
-moduledoc """
Build container rootfs from config.

Library module (no gen_server). Ties together the fuse store/manifest/ingest
modules with the container config. Returns a manifest, list of tmpfs mounts,
and an optional seccomp profile.

Handles the case where erlkoenig_fuse modules are NOT available
(returns error, lets container start without FUSE).
""".

-export([build/2, build/3]).

%%====================================================================
%% API
%%====================================================================

-doc "Build a container rootfs from config + store PID. Equivalent to build(Config, StorePid, #{}).".
-spec build(Config :: map(), StorePid :: pid()) ->
    {ok, #{manifest := term(),
           tmpfs_mounts := [#{path := binary(), size := binary()}],
           seccomp_profile => map()}} |
    {error, term()}.
build(Config, StorePid) ->
    build(Config, StorePid, #{}).

-doc """
Build a container rootfs from config + store PID + options.

Config is the rootfs-related container config (from extra_opts or DSL).
StorePid is the PID of erlkoenig_fuse_store.
Opts may contain:
  artifact_name - binary name for artifact store lookup (cached seccomp)

Returns:
  {ok, #{manifest, tmpfs_mounts, seccomp_profile}}
  {error, Reason}
""".
-spec build(Config :: map(), StorePid :: pid(), Opts :: map()) ->
    {ok, #{manifest := term(),
           tmpfs_mounts := [#{path := binary(), size := binary()}],
           seccomp_profile => map()}} |
    {error, term()}.
build(Config, StorePid, Opts) ->
    try
        %% 1. Check that erlkoenig_ingest is available
        case check_fuse_available() of
            ok ->
                do_build(Config, StorePid, Opts);
            {error, _} = Err ->
                Err
        end
    catch
        error:{badkey, Key} ->
            {error, {missing_config_key, Key}};
        Class:Reason:Stack ->
            logger:error("rootfs_builder failed: ~p:~p~n~p",
                         [Class, Reason, Stack]),
            {error, {Class, Reason}}
    end.

%%====================================================================
%% Internal
%%====================================================================

-spec check_fuse_available() -> ok | {error, fuse_not_available}.
check_fuse_available() ->
    try
        _ = erlkoenig_ingest:module_info(module),
        ok
    catch
        error:undef ->
            logger:warning("erlkoenig_fuse modules not available, "
                           "cannot build FUSE rootfs"),
            {error, fuse_not_available}
    end.

-spec do_build(map(), pid(), map()) ->
    {ok, #{manifest := term(),
           tmpfs_mounts := [#{path := binary(), size := binary()}],
           seccomp_profile => map()}} |
    {error, term()}.
do_build(Config, StorePid, Opts) ->
    %% 1. Extract rootfs spec from config
    RootfsSpec = maps:get(rootfs, Config, #{}),
    BinaryPath = maps:get(binary, Config, undefined),

    %% 2. Build the manifest via erlkoenig_ingest
    IngestSpec = case BinaryPath of
        undefined -> RootfsSpec;
        Path -> RootfsSpec#{binary => Path}
    end,
    case erlkoenig_ingest:build_rootfs(IngestSpec, StorePid) of
        {ok, Manifest} ->
            %% 3. Extract tmpfs mounts (these are NOT in the CAS)
            TmpfsMounts = maps:get(tmpfs, RootfsSpec, []),

            %% 4. Get or generate seccomp profile
            SeccompProfile = resolve_seccomp(Config, BinaryPath, Opts),

            {ok, #{
                manifest => Manifest,
                tmpfs_mounts => TmpfsMounts,
                seccomp_profile => SeccompProfile
            }};
        {error, Reason} ->
            {error, {ingest_failed, Reason}}
    end.

%%--------------------------------------------------------------------
%% Seccomp profile resolution:
%% 1. If config says seccomp => auto -> generate from ELF analysis
%% 2. If config has explicit seccomp profile map -> use that
%% 3. If artifact store has a cached profile -> use that
%% 4. Default: empty map (no custom seccomp)
%%--------------------------------------------------------------------

-spec resolve_seccomp(map(), binary() | undefined, map()) -> map().
resolve_seccomp(Config, BinaryPath, Opts) ->
    case maps:get(seccomp, Config, undefined) of
        auto ->
            generate_seccomp(BinaryPath);
        undefined ->
            %% Check artifact store for cached profile
            case maps:get(artifact_name, Opts, undefined) of
                undefined -> #{};
                Name -> lookup_cached_seccomp(Name)
            end;
        Profile when is_map(Profile) ->
            Profile;
        _Other ->
            #{}
    end.

-spec generate_seccomp(binary() | undefined) -> map().
generate_seccomp(undefined) ->
    #{};
generate_seccomp(BinaryPath) ->
    %% Try erlkoenig_elf if available
    try
        case erlkoenig_elf:parse(BinaryPath) of
            {ok, Elf} ->
                case erlkoenig_elf:seccomp_profile(Elf) of
                    {ok, Profile} -> Profile;
                    _ -> #{}
                end;
            _ -> #{}
        end
    catch
        error:undef ->
            %% erlkoenig_elf not available
            logger:info("erlkoenig_elf not available, skipping seccomp generation"),
            #{};
        _:_ ->
            #{}
    end.

-spec lookup_cached_seccomp(binary()) -> map().
lookup_cached_seccomp(Name) ->
    try
        case erlkoenig_artifact_store:lookup(Name) of
            {ok, #{seccomp_profile := Profile}}
              when is_map(Profile), map_size(Profile) > 0 ->
                Profile;
            _ -> #{}
        end
    catch
        _:_ -> #{}
    end.
