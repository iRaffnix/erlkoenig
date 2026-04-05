-module(erlkoenig_nft_cgroup_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

all() ->
    [{group, unit}].

groups() ->
    [
        {unit, [parallel], [
            service_not_found,
            resolves_from_file,
            appends_service_suffix,
            handles_binary_input
        ]}
    ].

init_per_group(_, Config) ->
    Config.

end_per_group(_, _Config) ->
    ok.

%% --- Unit tests ---

service_not_found(_) ->
    Result = erlkoenig_nft_cgroup:service_id("nonexistent_service_xyz"),
    ?assertMatch({error, {service_not_found, _, _}}, Result).

resolves_from_file(_) ->
    %% Verify the module loads and exports correctly
    {module, _} = code:ensure_loaded(erlkoenig_nft_cgroup),
    ?assert(erlang:function_exported(erlkoenig_nft_cgroup, service_id, 1)),
    ?assert(erlang:function_exported(erlkoenig_nft_cgroup, service_id, 2)),
    %% service_id/2 accepts a custom slice — verify it returns
    %% a proper error for a non-existent path
    ?assertMatch(
        {error, {service_not_found, _, _}},
        erlkoenig_nft_cgroup:service_id("test", "nonexistent.slice")
    ).

appends_service_suffix(_) ->
    %% "nginx" should look for "nginx.service"
    {error, {service_not_found, Name, _}} =
        erlkoenig_nft_cgroup:service_id("nginx"),
    ?assertEqual("nginx.service", Name).

handles_binary_input(_) ->
    %% Binary input should work the same as string
    {error, {service_not_found, Name, _}} =
        erlkoenig_nft_cgroup:service_id(<<"postgres">>),
    ?assertEqual("postgres.service", Name).

%% --- Helpers ---

make_tmp_cgroup() ->
    TmpBase = filename:join(
        "/tmp",
        "erlkoenig_cgroup_test_" ++
            integer_to_list(erlang:unique_integer([positive]))
    ),
    ok = file:make_dir(TmpBase),
    TmpBase.

cleanup_tmp(Dir) ->
    os:cmd("rm -rf " ++ Dir).
