%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_mount_opts_tests).
-include_lib("eunit/include/eunit.hrl").

%% Linux MS_* constants (mirror of module-internal defines).
-define(MS_RDONLY,      16#00000001).
-define(MS_NOSUID,      16#00000002).
-define(MS_NODEV,       16#00000004).
-define(MS_NOEXEC,      16#00000008).
-define(MS_REMOUNT,     16#00000020).
-define(MS_NOATIME,     16#00000400).
-define(MS_NODIRATIME,  16#00000800).
-define(MS_BIND,        16#00001000).
-define(MS_REC,         16#00004000).
-define(MS_RELATIME,    16#00200000).
-define(MS_STRICTATIME, 16#01000000).

%%====================================================================
%% Basic parse
%%====================================================================

parse_empty_test() ->
    ?assertEqual({ok, erlkoenig_mount_opts:default()},
                 erlkoenig_mount_opts:parse(<<"">>)).

parse_whitespace_only_test() ->
    ?assertEqual({ok, erlkoenig_mount_opts:default()},
                 erlkoenig_mount_opts:parse(<<"  , ,, ">>)).

parse_iodata_accepted_test() ->
    %% DSL often builds strings with io_lib:format returning iolist.
    {ok, Opts} = erlkoenig_mount_opts:parse(["r", "o"]),
    ?assertEqual(?MS_RDONLY, maps:get(flags, Opts)).

%%====================================================================
%% Single-flag
%%====================================================================

parse_ro_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"ro">>),
    ?assertEqual(?MS_RDONLY, maps:get(flags, Opts)),
    ?assertEqual(0, maps:get(clear, Opts)).

parse_rw_clears_rdonly_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"rw">>),
    ?assertEqual(0, maps:get(flags, Opts)),
    ?assertEqual(?MS_RDONLY, maps:get(clear, Opts)).

parse_nosuid_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"nosuid">>),
    ?assertEqual(?MS_NOSUID, maps:get(flags, Opts)).

parse_nodev_noexec_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"nodev,noexec">>),
    ?assertEqual(?MS_NODEV bor ?MS_NOEXEC, maps:get(flags, Opts)).

parse_remount_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"remount,ro">>),
    ?assertEqual(?MS_REMOUNT bor ?MS_RDONLY, maps:get(flags, Opts)).

%%====================================================================
%% Atime family — mutual exclusion
%%====================================================================

parse_relatime_clears_noatime_and_strictatime_test() ->
    %% Set noatime first, then override with relatime. Final state:
    %% MS_RELATIME set; MS_NOATIME must be cleared (last-wins within
    %% the atime family).
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"noatime,relatime">>),
    ?assertEqual(?MS_RELATIME, maps:get(flags, Opts) band ?MS_RELATIME),
    ?assertEqual(0,            maps:get(flags, Opts) band ?MS_NOATIME),
    ?assertEqual(0,            maps:get(flags, Opts) band ?MS_STRICTATIME).

parse_strictatime_clears_relatime_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"relatime,strictatime">>),
    ?assertEqual(?MS_STRICTATIME,
                 maps:get(flags, Opts) band ?MS_STRICTATIME),
    ?assertEqual(0, maps:get(flags, Opts) band ?MS_RELATIME).

%%====================================================================
%% Bind + recursion
%%====================================================================

parse_bind_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"bind">>),
    ?assertEqual(?MS_BIND, maps:get(flags, Opts)),
    ?assertEqual(0, maps:get(flags, Opts) band ?MS_REC).

parse_rbind_sets_both_bind_and_rec_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"rbind">>),
    ?assertEqual(?MS_BIND bor ?MS_REC, maps:get(flags, Opts)).

%%====================================================================
%% Propagation
%%====================================================================

parse_shared_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"shared">>),
    ?assertEqual(shared, maps:get(propagation, Opts)),
    ?assertEqual(false,  maps:get(recursive, Opts)).

parse_rprivate_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"rprivate">>),
    ?assertEqual(private, maps:get(propagation, Opts)),
    ?assertEqual(true,    maps:get(recursive, Opts)).

parse_rejects_conflicting_propagation_test() ->
    ?assertEqual({error, {conflicting_propagation, private, shared}},
                 erlkoenig_mount_opts:parse(<<"private,shared">>)).

parse_tolerates_repeated_propagation_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"private,private">>),
    ?assertEqual(private, maps:get(propagation, Opts)).

%%====================================================================
%% Data passthrough
%%====================================================================

parse_data_passthrough_single_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"size=64m">>),
    ?assertEqual(<<"size=64m">>, maps:get(data, Opts)),
    ?assertEqual(0, maps:get(flags, Opts)).

parse_data_and_flags_mixed_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(
                   <<"nosuid,size=64m,mode=0755,noexec">>),
    ?assertEqual(?MS_NOSUID bor ?MS_NOEXEC, maps:get(flags, Opts)),
    ?assertEqual(<<"size=64m,mode=0755">>, maps:get(data, Opts)).

parse_preserves_data_order_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(
                   <<"uid=1000,gid=1000,mode=0700">>),
    ?assertEqual(<<"uid=1000,gid=1000,mode=0700">>, maps:get(data, Opts)).

%%====================================================================
%% Strictness
%%====================================================================

parse_unknown_bare_token_raises_test() ->
    ?assertEqual({error, {unknown_flag, <<"nosudi">>}},
                 erlkoenig_mount_opts:parse(<<"nosudi">>)).

parse_unknown_midchain_bare_raises_test() ->
    ?assertEqual({error, {unknown_flag, <<"nodv">>}},
                 erlkoenig_mount_opts:parse(<<"ro,nodv,noexec">>)).

parse_unknown_key_value_accepted_as_data_test() ->
    %% Unknown keys are for the fs driver to validate — not our job.
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"unknown=opt">>),
    ?assertEqual(<<"unknown=opt">>, maps:get(data, Opts)).

parse_ro_then_rw_is_last_wins_test() ->
    %% mount(8) semantics: later wins. We chose this over strict
    %% rejection to stay predictable for operators used to the
    %% standard tooling.
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"ro,rw">>),
    ?assertEqual(0, maps:get(flags, Opts) band ?MS_RDONLY),
    ?assertEqual(?MS_RDONLY, maps:get(clear, Opts)).

parse_nosuid_then_suid_is_last_wins_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"nosuid,suid">>),
    ?assertEqual(0, maps:get(flags, Opts) band ?MS_NOSUID),
    ?assertEqual(?MS_NOSUID, maps:get(clear, Opts)).

%%====================================================================
%% Format / round-trip
%%====================================================================

format_default_is_empty_test() ->
    ?assertEqual(<<"">>, erlkoenig_mount_opts:format(
                            erlkoenig_mount_opts:default())).

format_ro_nosuid_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"ro,nosuid">>),
    ?assertEqual(<<"ro,nosuid">>, erlkoenig_mount_opts:format(Opts)).

format_rbind_canonicalises_test() ->
    %% bind+rec is expressed as `rbind` on the output side, matching
    %% mount(8) canonical form. Input via `rbind` directly.
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"rbind">>),
    ?assertEqual(<<"rbind">>, erlkoenig_mount_opts:format(Opts)).

format_with_data_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"nosuid,size=64m">>),
    ?assertEqual(<<"nosuid,size=64m">>, erlkoenig_mount_opts:format(Opts)).

format_with_propagation_test() ->
    {ok, Opts} = erlkoenig_mount_opts:parse(<<"nosuid,rslave">>),
    ?assertEqual(<<"nosuid,rslave">>, erlkoenig_mount_opts:format(Opts)).

round_trip_complex_test() ->
    S = <<"ro,nosuid,nodev,noexec,rslave,mode=0755">>,
    {ok, Opts1} = erlkoenig_mount_opts:parse(S),
    Formatted = erlkoenig_mount_opts:format(Opts1),
    {ok, Opts2} = erlkoenig_mount_opts:parse(Formatted),
    ?assertEqual(Opts1, Opts2).

%%====================================================================
%% flag_bits/1 introspection
%%====================================================================

flag_bits_known_test() ->
    ?assertEqual({?MS_NOSUID, 0},
                 erlkoenig_mount_opts:flag_bits(<<"nosuid">>)).

flag_bits_unknown_test() ->
    ?assertEqual(undefined,
                 erlkoenig_mount_opts:flag_bits(<<"bogus">>)).

%%====================================================================
%% Realistic recipes
%%====================================================================

recipe_ro_nosuid_nodev_noexec_test() ->
    %% The hardened-volume recipe: classic untrusted-data-dir setting.
    {ok, Opts} = erlkoenig_mount_opts:parse(
                   <<"ro,nosuid,nodev,noexec">>),
    Want = ?MS_RDONLY bor ?MS_NOSUID bor ?MS_NODEV bor ?MS_NOEXEC,
    ?assertEqual(Want, maps:get(flags, Opts)),
    ?assertEqual(none, maps:get(propagation, Opts)),
    ?assertEqual(<<>>, maps:get(data, Opts)).

recipe_tmpfs_test() ->
    %% tmpfs passes fs-specific data to the kernel driver.
    {ok, Opts} = erlkoenig_mount_opts:parse(
                   <<"nosuid,nodev,size=4m,mode=0755">>),
    ?assertEqual(?MS_NOSUID bor ?MS_NODEV, maps:get(flags, Opts)),
    ?assertEqual(<<"size=4m,mode=0755">>, maps:get(data, Opts)).

recipe_bind_with_ro_then_remount_test() ->
    %% Initial bind with ro is rejected by the kernel; correct recipe
    %% is bind first, then remount with ro. The parser accepts both
    %% independently — it doesn't enforce kernel semantics, that's
    %% the runtime's job.
    {ok, Bind}    = erlkoenig_mount_opts:parse(<<"bind">>),
    {ok, Remount} = erlkoenig_mount_opts:parse(<<"bind,remount,ro">>),
    ?assertEqual(?MS_BIND, maps:get(flags, Bind)),
    ?assertEqual(?MS_BIND bor ?MS_REMOUNT bor ?MS_RDONLY,
                 maps:get(flags, Remount)).
