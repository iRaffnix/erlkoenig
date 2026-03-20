%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_artifact_store (DETS artifact registry).
%%%
%%% Each test starts its own gen_server with a unique temporary DETS
%%% file and cleans up after itself. No root or network required.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_artifact_store_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%%====================================================================
%% Helpers
%%====================================================================

setup() ->
    TmpDir = "/tmp/erlkoenig_artifact_test_" ++
             integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
    DetsPath = filename:join(TmpDir, "test_artifacts.dets"),
    {ok, Pid} = erlkoenig_artifact_store:start_link(DetsPath),
    {Pid, TmpDir, DetsPath}.

cleanup({Pid, TmpDir, _DetsPath}) ->
    unlink(Pid),
    gen_server:stop(Pid),
    os:cmd("rm -rf " ++ TmpDir).

test_artifact_info() ->
    #{
        manifest_hash => crypto:strong_rand_bytes(32),
        binary_hash => crypto:strong_rand_bytes(32),
        pushed_at => erlang:system_time(second),
        tags => [<<"v1.0.0">>],
        seccomp_profile => #{default_action => kill},
        elf_info => #{syscalls => [read, write, exit]}
    }.

test_artifact_info(Tags) ->
    Info = test_artifact_info(),
    Info#{tags => Tags}.

%%====================================================================
%% Test generator
%%====================================================================

artifact_store_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun register_lookup/1,
      fun register_overwrite/1,
      fun lookup_not_found/1,
      fun list_empty/1,
      fun list_multiple/1,
      fun delete_artifact/1,
      fun tag_artifact/1,
      fun untag_artifact/1,
      fun lookup_by_tag_found/1,
      fun lookup_by_tag_not_found/1,
      fun tag_idempotent/1,
      fun delete_then_lookup/1
     ]}.

%%====================================================================
%% Persistence test (separate — needs stop/restart)
%%====================================================================

persistence_test_() ->
    {"DETS persistence across restarts",
     fun() ->
         TmpDir = "/tmp/erlkoenig_artifact_persist_" ++
                  integer_to_list(erlang:unique_integer([positive])),
         ok = filelib:ensure_dir(filename:join(TmpDir, "x")),
         DetsPath = filename:join(TmpDir, "persist.dets"),

         %% Start, register, stop
         {ok, Pid1} = erlkoenig_artifact_store:start_link(DetsPath),
         Info = test_artifact_info(),
         ok = erlkoenig_artifact_store:register(<<"web-v1.0.0">>, Info),
         gen_server:stop(Pid1),

         %% Start again with same path — data must survive
         {ok, Pid2} = erlkoenig_artifact_store:start_link(DetsPath),
         {ok, Got} = erlkoenig_artifact_store:lookup(<<"web-v1.0.0">>),
         ?assertEqual(maps:get(manifest_hash, Info),
                      maps:get(manifest_hash, Got)),
         ?assertEqual(maps:get(binary_hash, Info),
                      maps:get(binary_hash, Got)),
         ?assertEqual(maps:get(tags, Info),
                      maps:get(tags, Got)),
         gen_server:stop(Pid2),
         os:cmd("rm -rf " ++ TmpDir)
     end}.

%%====================================================================
%% Individual test functions
%%====================================================================

register_lookup({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info = test_artifact_info(),
        ok = erlkoenig_artifact_store:register(<<"web-v1.0.0">>, Info),
        {ok, Got} = erlkoenig_artifact_store:lookup(<<"web-v1.0.0">>),
        %% Name is added by register
        ?assertEqual(<<"web-v1.0.0">>, maps:get(name, Got)),
        %% All fields preserved
        ?assertEqual(maps:get(manifest_hash, Info),
                     maps:get(manifest_hash, Got)),
        ?assertEqual(maps:get(binary_hash, Info),
                     maps:get(binary_hash, Got)),
        ?assertEqual(maps:get(pushed_at, Info),
                     maps:get(pushed_at, Got)),
        ?assertEqual(maps:get(tags, Info),
                     maps:get(tags, Got)),
        ?assertEqual(maps:get(seccomp_profile, Info),
                     maps:get(seccomp_profile, Got)),
        ?assertEqual(maps:get(elf_info, Info),
                     maps:get(elf_info, Got))
    end.

register_overwrite({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info1 = test_artifact_info([<<"v1">>]),
        Info2 = test_artifact_info([<<"v2">>]),
        ok = erlkoenig_artifact_store:register(<<"app">>, Info1),
        ok = erlkoenig_artifact_store:register(<<"app">>, Info2),
        {ok, Got} = erlkoenig_artifact_store:lookup(<<"app">>),
        %% Second registration wins
        ?assertEqual(maps:get(binary_hash, Info2),
                     maps:get(binary_hash, Got)),
        ?assertEqual([<<"v2">>], maps:get(tags, Got))
    end.

lookup_not_found({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ?assertEqual({error, not_found},
                     erlkoenig_artifact_store:lookup(<<"nonexistent">>))
    end.

list_empty({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ?assertEqual([], erlkoenig_artifact_store:list())
    end.

list_multiple({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ok = erlkoenig_artifact_store:register(<<"a">>, test_artifact_info()),
        ok = erlkoenig_artifact_store:register(<<"b">>, test_artifact_info()),
        ok = erlkoenig_artifact_store:register(<<"c">>, test_artifact_info()),
        All = erlkoenig_artifact_store:list(),
        ?assertEqual(3, length(All)),
        Names = lists:sort([maps:get(name, I) || I <- All]),
        ?assertEqual([<<"a">>, <<"b">>, <<"c">>], Names)
    end.

delete_artifact({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ok = erlkoenig_artifact_store:register(<<"doomed">>, test_artifact_info()),
        {ok, _} = erlkoenig_artifact_store:lookup(<<"doomed">>),
        ok = erlkoenig_artifact_store:delete(<<"doomed">>),
        ?assertEqual({error, not_found},
                     erlkoenig_artifact_store:lookup(<<"doomed">>))
    end.

tag_artifact({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info = test_artifact_info([]),
        ok = erlkoenig_artifact_store:register(<<"web-v2">>, Info),
        ok = erlkoenig_artifact_store:tag(<<"web-v2">>, <<"production">>),
        {ok, Got} = erlkoenig_artifact_store:lookup(<<"web-v2">>),
        Tags = maps:get(tags, Got),
        ?assert(lists:member(<<"production">>, Tags))
    end.

untag_artifact({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info = test_artifact_info([<<"staging">>, <<"production">>]),
        ok = erlkoenig_artifact_store:register(<<"web-v3">>, Info),
        ok = erlkoenig_artifact_store:untag(<<"web-v3">>, <<"staging">>),
        {ok, Got} = erlkoenig_artifact_store:lookup(<<"web-v3">>),
        Tags = maps:get(tags, Got),
        ?assertNot(lists:member(<<"staging">>, Tags)),
        ?assert(lists:member(<<"production">>, Tags))
    end.

lookup_by_tag_found({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info = test_artifact_info([<<"latest">>, <<"v1.0.0">>]),
        ok = erlkoenig_artifact_store:register(<<"web-v1.0.0">>, Info),
        %% Prefix "web" + tag "latest" should find it
        {ok, Got} = erlkoenig_artifact_store:lookup_by_tag(<<"web">>, <<"latest">>),
        ?assertEqual(<<"web-v1.0.0">>, maps:get(name, Got))
    end.

lookup_by_tag_not_found({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info = test_artifact_info([<<"v1.0.0">>]),
        ok = erlkoenig_artifact_store:register(<<"web-v1.0.0">>, Info),
        %% Wrong tag
        ?assertEqual({error, not_found},
                     erlkoenig_artifact_store:lookup_by_tag(<<"web">>, <<"production">>)),
        %% Wrong prefix
        ?assertEqual({error, not_found},
                     erlkoenig_artifact_store:lookup_by_tag(<<"api">>, <<"v1.0.0">>))
    end.

tag_idempotent({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        Info = test_artifact_info([<<"v1">>]),
        ok = erlkoenig_artifact_store:register(<<"app">>, Info),
        ok = erlkoenig_artifact_store:tag(<<"app">>, <<"latest">>),
        ok = erlkoenig_artifact_store:tag(<<"app">>, <<"latest">>),
        ok = erlkoenig_artifact_store:tag(<<"app">>, <<"latest">>),
        {ok, Got} = erlkoenig_artifact_store:lookup(<<"app">>),
        Tags = maps:get(tags, Got),
        %% "latest" should appear exactly once despite 3 tag calls
        LatestCount = length([T || T <- Tags, T =:= <<"latest">>]),
        ?assertEqual(1, LatestCount)
    end.

delete_then_lookup({_Pid, _TmpDir, _DetsPath}) ->
    fun() ->
        ok = erlkoenig_artifact_store:register(<<"temp">>, test_artifact_info()),
        ok = erlkoenig_artifact_store:delete(<<"temp">>),
        ?assertEqual({error, not_found},
                     erlkoenig_artifact_store:lookup(<<"temp">>)),
        %% Deleting again should not crash
        ok = erlkoenig_artifact_store:delete(<<"temp">>)
    end.
