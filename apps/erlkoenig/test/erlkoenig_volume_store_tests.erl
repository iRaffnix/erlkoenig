%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_volume_store (DETS + gen_server).
%%%
%%% Exercises: UUID generation, idempotent ensure, list, destroy,
%%% ephemeral cleanup, by-name symlinks, chown best-effort.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_volume_store_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

store_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(Root) ->
         [{"ensure creates a UUID dir on disk",
           ?_test(t_ensure_creates_dir(Root))},
          {"ensure is idempotent for same (container, persist)",
           ?_test(t_ensure_idempotent())},
          {"different (container, persist) pairs get distinct UUIDs",
           ?_test(t_distinct_uuids())},
          {"find returns the stored record",
           ?_test(t_find())},
          {"find returns not_found for unknown pair",
           ?_test(t_find_missing())},
          {"list returns everything",
           ?_test(t_list())},
          {"list_by_container filters correctly",
           ?_test(t_list_by_container())},
          {"destroy removes metadata + on-disk dir",
           ?_test(t_destroy())},
          {"destroy on unknown uuid returns {error, not_found}",
           ?_test(t_destroy_missing())},
          {"cleanup_ephemeral only touches ephemeral volumes",
           ?_test(t_cleanup_ephemeral())},
          {"by-name symlink points to UUID dir",
           ?_test(t_by_name_symlink(Root))},
          {"quota field flows from ensure into record",
           ?_test(t_quota_on_create())},
          {"set_quota on existing volume updates metadata",
           ?_test(t_set_quota())},
          {"set_quota bytes=0 clears the limit",
           ?_test(t_clear_quota())},
          {"re-ensure with a new quota reconciles the record",
           ?_test(t_reconcile_quota())},
          {"distinct volumes get distinct project IDs",
           ?_test(t_distinct_project_ids())},
          {"parse_quota accepts strings, ints, binaries",
           ?_test(t_parse_quota())},
          {"parse_quota raises on garbage",
           ?_test(t_parse_quota_invalid())}]
     end}.

%%====================================================================
%% Fixture
%%====================================================================

setup() ->
    Root = iolist_to_binary(["/tmp/eunit_ek_vs_",
                             integer_to_list(erlang:system_time(nanosecond))]),
    ok = application:set_env(erlkoenig, volumes_root, Root),
    case erlkoenig_volume_store:start_link() of
        {ok, _Pid} -> ok;
        {error, {already_started, _}} -> ok
    end,
    Root.

cleanup(Root) ->
    case whereis(erlkoenig_volume_store) of
        undefined -> ok;
        Pid -> gen_server:stop(Pid, normal, 5000)
    end,
    _ = application:unset_env(erlkoenig, volumes_root),
    _ = file:del_dir_r(binary_to_list(Root)),
    ok.

%%====================================================================
%% Tests
%%====================================================================

t_ensure_creates_dir(Root) ->
    {ok, V} = erlkoenig_volume_store:ensure(
        #{container => <<"ct1">>, persist => <<"data">>,
          uid => 1000, gid => 1000}),
    Host = maps:get(host_path, V),
    ?assert(binary:match(Host, Root) =/= nomatch),
    ?assert(filelib:is_dir(binary_to_list(Host))),
    ?assertMatch(<<"ek_vol_", _/binary>>, maps:get(uuid, V)).

t_ensure_idempotent() ->
    Req = #{container => <<"ct2">>, persist => <<"db">>,
            uid => 1000, gid => 1000},
    {ok, V1} = erlkoenig_volume_store:ensure(Req),
    {ok, V2} = erlkoenig_volume_store:ensure(Req),
    ?assertEqual(maps:get(uuid, V1), maps:get(uuid, V2)),
    ?assertEqual(maps:get(host_path, V1), maps:get(host_path, V2)),
    ?assertEqual(maps:get(created_at, V1), maps:get(created_at, V2)).

t_distinct_uuids() ->
    {ok, A} = erlkoenig_volume_store:ensure(
        #{container => <<"ct3">>, persist => <<"a">>,
          uid => 0, gid => 0}),
    {ok, B} = erlkoenig_volume_store:ensure(
        #{container => <<"ct3">>, persist => <<"b">>,
          uid => 0, gid => 0}),
    {ok, C} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-other">>, persist => <<"a">>,
          uid => 0, gid => 0}),
    UuidA = maps:get(uuid, A),
    UuidB = maps:get(uuid, B),
    UuidC = maps:get(uuid, C),
    ?assertNotEqual(UuidA, UuidB),
    ?assertNotEqual(UuidA, UuidC),
    ?assertNotEqual(UuidB, UuidC).

t_find() ->
    {ok, V} = erlkoenig_volume_store:ensure(
        #{container => <<"ct4">>, persist => <<"logs">>,
          uid => 0, gid => 0}),
    ?assertEqual({ok, V},
                 erlkoenig_volume_store:find(<<"ct4">>, <<"logs">>)).

t_find_missing() ->
    ?assertEqual(not_found,
                 erlkoenig_volume_store:find(<<"nope">>, <<"nada">>)).

t_list() ->
    {ok, _} = erlkoenig_volume_store:ensure(
        #{container => <<"list-a">>, persist => <<"v">>,
          uid => 0, gid => 0}),
    {ok, _} = erlkoenig_volume_store:ensure(
        #{container => <<"list-b">>, persist => <<"v">>,
          uid => 0, gid => 0}),
    All = erlkoenig_volume_store:list(),
    Names = [maps:get(container, V) || V <- All],
    ?assert(lists:member(<<"list-a">>, Names)),
    ?assert(lists:member(<<"list-b">>, Names)).

t_list_by_container() ->
    {ok, _} = erlkoenig_volume_store:ensure(
        #{container => <<"lb-a">>, persist => <<"one">>,
          uid => 0, gid => 0}),
    {ok, _} = erlkoenig_volume_store:ensure(
        #{container => <<"lb-a">>, persist => <<"two">>,
          uid => 0, gid => 0}),
    {ok, _} = erlkoenig_volume_store:ensure(
        #{container => <<"lb-b">>, persist => <<"other">>,
          uid => 0, gid => 0}),
    A = erlkoenig_volume_store:list_by_container(<<"lb-a">>),
    ?assertEqual(2, length(A)),
    ?assert(lists:all(fun(V) ->
                           maps:get(container, V) =:= <<"lb-a">>
                       end, A)).

t_destroy() ->
    {ok, V} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-d">>, persist => <<"gone">>,
          uid => 0, gid => 0}),
    Host = maps:get(host_path, V),
    ?assert(filelib:is_dir(binary_to_list(Host))),
    ok = erlkoenig_volume_store:destroy(maps:get(uuid, V)),
    ?assertNot(filelib:is_dir(binary_to_list(Host))),
    ?assertEqual(not_found,
                 erlkoenig_volume_store:find(<<"ct-d">>, <<"gone">>)).

t_destroy_missing() ->
    ?assertEqual({error, not_found},
                 erlkoenig_volume_store:destroy(<<"ek_vol_notreal">>)).

t_cleanup_ephemeral() ->
    %% Mix persistent + ephemeral under one container.
    {ok, Persist} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-eph">>, persist => <<"keep">>,
          uid => 0, gid => 0, lifecycle => persistent}),
    {ok, Eph} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-eph">>, persist => <<"tmp">>,
          uid => 0, gid => 0, lifecycle => ephemeral}),
    {ok, Destroyed} = erlkoenig_volume_store:cleanup_ephemeral(<<"ct-eph">>),
    ?assertEqual([maps:get(uuid, Eph)], Destroyed),
    %% Persistent volume is untouched.
    ?assertMatch({ok, _},
                 erlkoenig_volume_store:find(<<"ct-eph">>, <<"keep">>)),
    ?assert(filelib:is_dir(binary_to_list(maps:get(host_path, Persist)))),
    %% Ephemeral is gone.
    ?assertEqual(not_found,
                 erlkoenig_volume_store:find(<<"ct-eph">>, <<"tmp">>)),
    ?assertNot(filelib:is_dir(binary_to_list(maps:get(host_path, Eph)))).

t_by_name_symlink(Root) ->
    {ok, V} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-sym">>, persist => <<"linked">>,
          uid => 0, gid => 0}),
    LinkPath = filename:join([binary_to_list(Root), "by-name",
                              "ct-sym", "linked"]),
    ?assertMatch({ok, #file_info{type = symlink}},
                 file:read_link_info(LinkPath)),
    {ok, Target} = file:read_link(LinkPath),
    ?assertEqual("../../" ++ binary_to_list(maps:get(uuid, V)), Target).

%%====================================================================
%% Quota tests
%%
%% The test tmpdir isn't XFS, so `xfs_quota` will fail at the
%% subprocess layer. That's by design — the store logs a warning
%% and records the requested quota in metadata regardless. These
%% tests verify the metadata pathway; kernel-level enforcement is
%% covered by integration test 28 (root-gated, real XFS mount).
%%====================================================================

t_quota_on_create() ->
    {ok, V} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-q">>, persist => <<"sized">>,
          uid => 0, gid => 0,
          quota => <<"1G">>}),
    ?assertEqual(1073741824, maps:get(quota_bytes, V)),
    ?assert(maps:get(project_id, V) >= 10_000).

t_set_quota() ->
    {ok, V0} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-sq">>, persist => <<"x">>,
          uid => 0, gid => 0}),
    %% No quota yet.
    ?assertEqual(error, maps:find(quota_bytes, V0)),
    {ok, V1} = erlkoenig_volume_store:set_quota(
        maps:get(uuid, V0), <<"500M">>),
    ?assertEqual(500 * 1024 * 1024, maps:get(quota_bytes, V1)),
    ?assert(maps:get(project_id, V1) >= 10_000),
    %% find/2 sees the new quota too.
    {ok, Found} = erlkoenig_volume_store:find(<<"ct-sq">>, <<"x">>),
    ?assertEqual(500 * 1024 * 1024, maps:get(quota_bytes, Found)).

t_clear_quota() ->
    {ok, V0} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-cq">>, persist => <<"x">>,
          uid => 0, gid => 0, quota => <<"100M">>}),
    {ok, V1} = erlkoenig_volume_store:set_quota(
        maps:get(uuid, V0), 0),
    ?assertEqual(error, maps:find(quota_bytes, V1)),
    %% Project ID stays bound — cheaper to reuse on the next raise.
    ?assertEqual(maps:get(project_id, V0), maps:get(project_id, V1)).

t_reconcile_quota() ->
    %% First ensure: 1G.
    {ok, V1} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-rec">>, persist => <<"y">>,
          uid => 0, gid => 0, quota => <<"1G">>}),
    ?assertEqual(1073741824, maps:get(quota_bytes, V1)),
    %% Second ensure with a different quota → store reconciles to 2G.
    {ok, V2} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-rec">>, persist => <<"y">>,
          uid => 0, gid => 0, quota => <<"2G">>}),
    ?assertEqual(2 * 1073741824, maps:get(quota_bytes, V2)),
    %% Same UUID and project ID — the record is updated in place.
    ?assertEqual(maps:get(uuid, V1), maps:get(uuid, V2)),
    ?assertEqual(maps:get(project_id, V1), maps:get(project_id, V2)).

t_distinct_project_ids() ->
    {ok, A} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-d">>, persist => <<"pa">>,
          uid => 0, gid => 0, quota => <<"1G">>}),
    {ok, B} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-d">>, persist => <<"pb">>,
          uid => 0, gid => 0, quota => <<"1G">>}),
    {ok, C} = erlkoenig_volume_store:ensure(
        #{container => <<"ct-other">>, persist => <<"pc">>,
          uid => 0, gid => 0, quota => <<"1G">>}),
    PidA = maps:get(project_id, A),
    PidB = maps:get(project_id, B),
    PidC = maps:get(project_id, C),
    ?assertNotEqual(PidA, PidB),
    ?assertNotEqual(PidA, PidC),
    ?assertNotEqual(PidB, PidC),
    ?assert(PidA >= 10_000).

t_parse_quota() ->
    ?assertEqual(0, erlkoenig_volume_store:parse_quota(0)),
    ?assertEqual(0, erlkoenig_volume_store:parse_quota(<<"">>)),
    ?assertEqual(1024, erlkoenig_volume_store:parse_quota(1024)),
    ?assertEqual(1024, erlkoenig_volume_store:parse_quota(<<"1K">>)),
    ?assertEqual(1048576, erlkoenig_volume_store:parse_quota(<<"1M">>)),
    ?assertEqual(1073741824, erlkoenig_volume_store:parse_quota(<<"1G">>)),
    %% Lowercase + KB/MB/GB suffixes also accepted.
    ?assertEqual(1024, erlkoenig_volume_store:parse_quota(<<"1k">>)),
    ?assertEqual(1024, erlkoenig_volume_store:parse_quota(<<"1KB">>)),
    ?assertEqual(1048576, erlkoenig_volume_store:parse_quota(<<"1MB">>)).

t_parse_quota_invalid() ->
    ?assertError({invalid_quota, _},
                 erlkoenig_volume_store:parse_quota(<<"1Z">>)),
    ?assertError({invalid_quota, _},
                 erlkoenig_volume_store:parse_quota(<<"garbage">>)),
    ?assertError({invalid_quota, _},
                 erlkoenig_volume_store:parse_quota(-1)).
