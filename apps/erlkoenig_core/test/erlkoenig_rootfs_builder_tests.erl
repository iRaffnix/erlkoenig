%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_rootfs_builder.
%%%
%%% Tests the rootfs builder library module which ties together
%%% erlkoenig_fuse_store, erlkoenig_ingest, and erlkoenig_fuse_manifest
%%% to build container rootfs manifests from config maps.
%%%
%%% Each test starts its own CAS store with a unique temp directory
%%% and cleans up after itself. No root or network required.
%%%
%%% Since erlkoenig_fuse is not a direct dependency, the ebin path
%%% is added at test setup time.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_rootfs_builder_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%%====================================================================
%% Helpers
%%====================================================================

ensure_fuse_available() ->
    case code:which(erlkoenig_fuse_store) of
        non_existing ->
            FuseEbin = "/home/erlkoenig/code/erlkoenig_fuse/_build/default/lib/erlkoenig_fuse/ebin",
            FuseInclude = "/home/erlkoenig/code/erlkoenig_fuse/include",
            true = code:add_patha(FuseEbin),
            %% Also need the .hrl — but since we don't include it in
            %% test code (only the modules we call do), ebin is enough.
            _ = FuseInclude,
            ok;
        _ ->
            ok
    end.

setup() ->
    ok = ensure_fuse_available(),

    TmpDir = "/tmp/erlkoenig_rootfs_test_" ++
             integer_to_list(erlang:unique_integer([positive])),
    StoreDir = filename:join(TmpDir, "store"),
    FilesDir = filename:join(TmpDir, "files"),
    ok = filelib:ensure_dir(filename:join(StoreDir, "x")),
    ok = filelib:ensure_dir(filename:join(FilesDir, "x")),

    %% Start the CAS store
    {ok, StorePid} = erlkoenig_fuse_store:start_link(StoreDir),

    %% Create test binary file
    BinaryPath = filename:join(FilesDir, "test-binary"),
    BinaryData = crypto:strong_rand_bytes(8192),
    ok = file:write_file(BinaryPath, BinaryData),
    ok = file:change_mode(BinaryPath, 8#755),

    %% Create test config file (host file for rootfs specs)
    ConfigPath = filename:join(FilesDir, "config.json"),
    ok = file:write_file(ConfigPath, <<"{\"port\": 8080}">>),

    {StorePid, TmpDir, FilesDir,
     list_to_binary(BinaryPath), list_to_binary(ConfigPath)}.

cleanup({StorePid, TmpDir, _FilesDir, _BinaryPath, _ConfigPath}) ->
    unlink(StorePid),
    gen_server:stop(StorePid),
    os:cmd("rm -rf " ++ TmpDir).

%%====================================================================
%% Test generator
%%====================================================================

rootfs_builder_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun build_simple/1,
      fun build_with_rootfs_spec/1,
      fun build_with_host_file/1,
      fun build_no_binary/1,
      fun build_returns_tmpfs/1,
      fun build_error_missing_binary/1,
      fun build_empty_config/1,
      fun build_seccomp_default/1,
      fun build_seccomp_explicit/1,
      fun build_with_inline_file/1
     ]}.

%%====================================================================
%% Test: simple build — binary path only, no rootfs block
%%====================================================================

build_simple({StorePid, _TmpDir, _FilesDir, BinaryPath, _ConfigPath}) ->
    {"Config with only binary path builds manifest with /app",
     fun() ->
         Config = #{binary => BinaryPath},
         {ok, Result} = erlkoenig_rootfs_builder:build(Config, StorePid),

         #{manifest := Manifest,
           tmpfs_mounts := TmpfsMounts,
           seccomp_profile := SeccompProfile} = Result,

         %% Manifest must contain the binary at /app
         {ok, Entry} = erlkoenig_fuse_manifest:lookup(Manifest, <<"app">>),
         ?assertMatch({cas_file, _, _, _}, Entry),

         %% No tmpfs mounts
         ?assertEqual([], TmpfsMounts),

         %% Seccomp profile is a map (empty since erlkoenig_elf unavailable)
         ?assert(is_map(SeccompProfile))
     end}.

%%====================================================================
%% Test: build with rootfs spec — binary + inline files
%%====================================================================

build_with_rootfs_spec({StorePid, _TmpDir, _FilesDir, BinaryPath, _ConfigPath}) ->
    {"Config with rootfs block containing binary + inline files",
     fun() ->
         RootfsSpec = #{
             files => [
                 #{path => <<"/etc/app/config.json">>,
                   source => {inline, <<"{\"key\": \"value\"}">>}},
                 #{path => <<"/etc/app/motd">>,
                   source => {inline, <<"Welcome">>}}
             ]
         },
         Config = #{binary => BinaryPath, rootfs => RootfsSpec},
         {ok, Result} = erlkoenig_rootfs_builder:build(Config, StorePid),

         #{manifest := Manifest} = Result,

         %% Binary at /app
         {ok, AppEntry} = erlkoenig_fuse_manifest:lookup(Manifest, <<"app">>),
         ?assertMatch({cas_file, _, _, _}, AppEntry),

         %% Inline files present
         {ok, CfgEntry} = erlkoenig_fuse_manifest:lookup(
             Manifest, <<"/etc/app/config.json">>),
         ?assertMatch({cas_file, _, _, _}, CfgEntry),

         {ok, MotdEntry} = erlkoenig_fuse_manifest:lookup(
             Manifest, <<"/etc/app/motd">>),
         ?assertMatch({cas_file, _, _, _}, MotdEntry)
     end}.

%%====================================================================
%% Test: build with host file in rootfs spec
%%====================================================================

build_with_host_file({StorePid, _TmpDir, _FilesDir, BinaryPath, ConfigPath}) ->
    {"Config with rootfs including a host file maps correctly",
     fun() ->
         RootfsSpec = #{
             files => [
                 #{path => <<"/etc/myapp/config.json">>,
                   source => {host, ConfigPath}}
             ]
         },
         Config = #{binary => BinaryPath, rootfs => RootfsSpec},
         {ok, Result} = erlkoenig_rootfs_builder:build(Config, StorePid),

         #{manifest := Manifest} = Result,

         %% Host file present at container path
         {ok, Entry} = erlkoenig_fuse_manifest:lookup(
             Manifest, <<"/etc/myapp/config.json">>),
         ?assertMatch({cas_file, _, _, _}, Entry),

         %% Verify size matches the config file we wrote
         {cas_file, _Mode, Size, _Blocks} = Entry,
         ?assertEqual(byte_size(<<"{\"port\": 8080}">>), Size)
     end}.

%%====================================================================
%% Test: build without binary — only extra files
%%====================================================================

build_no_binary({StorePid, _TmpDir, _FilesDir, _BinaryPath, _ConfigPath}) ->
    {"Config without binary builds manifest with only extra files",
     fun() ->
         RootfsSpec = #{
             files => [
                 #{path => <<"/etc/hostname">>,
                   source => {inline, <<"testhost">>}}
             ]
         },
         Config = #{rootfs => RootfsSpec},
         {ok, Result} = erlkoenig_rootfs_builder:build(Config, StorePid),

         #{manifest := Manifest} = Result,

         %% No /app entry (no binary)
         ?assertEqual({error, enoent},
                      erlkoenig_fuse_manifest:lookup(Manifest, <<"app">>)),

         %% But the extra file is there
         {ok, Entry} = erlkoenig_fuse_manifest:lookup(
             Manifest, <<"/etc/hostname">>),
         ?assertMatch({cas_file, _, _, _}, Entry)
     end}.

%%====================================================================
%% Test: tmpfs entries returned separately, NOT in manifest
%%====================================================================

build_returns_tmpfs({StorePid, _TmpDir, _FilesDir, BinaryPath, _ConfigPath}) ->
    {"tmpfs entries are in tmpfs_mounts, not in the manifest",
     fun() ->
         TmpfsList = [
             #{path => <<"/tmp">>, size => <<"64M">>},
             #{path => <<"/var/run">>, size => <<"16M">>}
         ],
         RootfsSpec = #{tmpfs => TmpfsList},
         Config = #{binary => BinaryPath, rootfs => RootfsSpec},
         {ok, Result} = erlkoenig_rootfs_builder:build(Config, StorePid),

         #{tmpfs_mounts := TmpfsMounts, manifest := Manifest} = Result,

         %% tmpfs_mounts returned as-is
         ?assertEqual(2, length(TmpfsMounts)),
         ?assert(lists:any(
             fun(#{path := P}) -> P =:= <<"/tmp">> end, TmpfsMounts)),
         ?assert(lists:any(
             fun(#{path := P}) -> P =:= <<"/var/run">> end, TmpfsMounts)),

         %% /tmp and /var/run should NOT be in the manifest as files
         ?assertEqual({error, enoent},
                      erlkoenig_fuse_manifest:lookup(Manifest, <<"tmp">>)),
         ?assertEqual({error, enoent},
                      erlkoenig_fuse_manifest:lookup(Manifest, <<"var/run">>))
     end}.

%%====================================================================
%% Test: missing binary path -> error
%%====================================================================

build_error_missing_binary({StorePid, _TmpDir, _FilesDir, _BinaryPath, _ConfigPath}) ->
    {"Non-existent binary path returns an error",
     fun() ->
         Config = #{binary => <<"/nonexistent/path/to/binary">>},
         Result = erlkoenig_rootfs_builder:build(Config, StorePid),
         ?assertMatch({error, _}, Result)
     end}.

%%====================================================================
%% Test: empty config -> builds empty manifest
%%====================================================================

build_empty_config({StorePid, _TmpDir, _FilesDir, _BinaryPath, _ConfigPath}) ->
    {"Empty config map builds empty manifest",
     fun() ->
         Config = #{},
         {ok, Result} = erlkoenig_rootfs_builder:build(Config, StorePid),

         #{manifest := Manifest,
           tmpfs_mounts := TmpfsMounts,
           seccomp_profile := SeccompProfile} = Result,

         %% Empty manifest — root dir with no children
         {ok, Entries} = erlkoenig_fuse_manifest:readdir(Manifest, <<"/">>),
         ?assertEqual([], Entries),

         %% No tmpfs
         ?assertEqual([], TmpfsMounts),

         %% Empty seccomp
         ?assert(is_map(SeccompProfile))
     end}.

%%====================================================================
%% Test: no seccomp config -> empty map returned
%%====================================================================

build_seccomp_default({StorePid, _TmpDir, _FilesDir, BinaryPath, _ConfigPath}) ->
    {"No seccomp config returns empty map (erlkoenig_elf not available)",
     fun() ->
         Config = #{binary => BinaryPath},
         {ok, Result} = erlkoenig_rootfs_builder:build(Config, StorePid),

         #{seccomp_profile := SeccompProfile} = Result,
         %% Without erlkoenig_elf available, seccomp defaults to empty
         ?assertEqual(#{}, SeccompProfile)
     end}.

%%====================================================================
%% Test: explicit seccomp profile in config is passed through
%%====================================================================

build_seccomp_explicit({StorePid, _TmpDir, _FilesDir, BinaryPath, _ConfigPath}) ->
    {"Explicit seccomp profile in config is returned as-is",
     fun() ->
         Profile = #{default_action => kill,
                     syscalls => [read, write, exit_group]},
         Config = #{binary => BinaryPath, seccomp => Profile},
         {ok, Result} = erlkoenig_rootfs_builder:build(Config, StorePid),

         #{seccomp_profile := SeccompProfile} = Result,
         ?assertEqual(Profile, SeccompProfile)
     end}.

%%====================================================================
%% Test: build with inline file verifies content size
%%====================================================================

build_with_inline_file({StorePid, _TmpDir, _FilesDir, BinaryPath, _ConfigPath}) ->
    {"Inline file has correct size in manifest entry",
     fun() ->
         Content = <<"Hello, Erlkoenig!">>,
         RootfsSpec = #{
             files => [
                 #{path => <<"/data/greeting.txt">>,
                   source => {inline, Content}}
             ]
         },
         Config = #{binary => BinaryPath, rootfs => RootfsSpec},
         {ok, Result} = erlkoenig_rootfs_builder:build(Config, StorePid),

         #{manifest := Manifest} = Result,

         {ok, Entry} = erlkoenig_fuse_manifest:lookup(
             Manifest, <<"/data/greeting.txt">>),
         {cas_file, _Mode, Size, _Blocks} = Entry,
         ?assertEqual(byte_size(Content), Size)
     end}.
