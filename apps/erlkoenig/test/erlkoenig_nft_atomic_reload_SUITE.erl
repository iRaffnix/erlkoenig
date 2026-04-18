-module(erlkoenig_nft_atomic_reload_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-include("nft_constants.hrl").

-define(INET, 1).
-define(TABLE, <<"erltest_atomic_reload">>).

all() ->
    [
        kernel_accepts_add_delete_add_in_one_batch,
        reload_replaces_objects_atomically
    ].

init_per_suite(Config) ->
    case os:cmd("id -u") of
        "0\n" ->
            case os:cmd("which nft") of
                [] -> {skip, "nft binary not present"};
                _ ->
                    {ok, _} = application:ensure_all_started(erlkoenig),
                    Config
            end;
        _ ->
            {skip, "kernel tests require root"}
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    %% Best-effort cleanup of stale artefacts
    cleanup(),
    Config.

end_per_testcase(_TC, _Config) ->
    cleanup(),
    ok.

cleanup() ->
    _ = nfnl_server:apply_msgs(erlkoenig_nft_srv,
            [fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
             fun(S) -> nft_delete:table(?INET, ?TABLE, S) end]),
    ok.

%% =================================================================
%% Test 1: the kernel accepts the add-delete-add idiom in one batch.
%%
%% This is the primitive that makes atomic reload possible. If a
%% future kernel ever rejects the sequence (e.g. by introducing a
%% pre-flight that flags "you are deleting an object you just added
%% in this transaction"), the whole reload guarantee collapses and
%% this test will catch it before it ships to production.
%% =================================================================

kernel_accepts_add_delete_add_in_one_batch(_) ->
    R = nfnl_server:apply_msgs(erlkoenig_nft_srv,
            [fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
             fun(S) -> nft_delete:table(?INET, ?TABLE, S) end,
             fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
             fun(S) -> nft_object:add_counter(?INET, ?TABLE,
                                              <<"some_counter">>, S) end]),
    ?assertEqual(ok, R),

    %% Same batch again — now the table exists from the previous run.
    %% The leading add is an idempotent upsert; the delete then succeeds;
    %% the second add re-creates. This is the security-critical path
    %% (every reload after the first one).
    R2 = nfnl_server:apply_msgs(erlkoenig_nft_srv,
            [fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
             fun(S) -> nft_delete:table(?INET, ?TABLE, S) end,
             fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
             fun(S) -> nft_object:add_counter(?INET, ?TABLE,
                                              <<"some_counter">>, S) end]),
    ?assertEqual(ok, R2).

%% =================================================================
%% Test 2: a reload that swaps objects actually swaps them.
%%
%% Install with counter_A, then reload with counter_B (no counter_A).
%% After reload, counter_A must be gone and counter_B must be fresh.
%% This proves the new state replaces the old, rather than merging.
%% =================================================================

reload_replaces_objects_atomically(_) ->
    %% Phase 1: install with counter_A only
    ok = nfnl_server:apply_msgs(erlkoenig_nft_srv,
            [fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
             fun(S) -> nft_delete:table(?INET, ?TABLE, S) end,
             fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
             fun(S) -> nft_object:add_counter(?INET, ?TABLE,
                                              <<"counter_A">>, S) end]),

    {ok, #{packets := 0}} =
        nfnl_server:get_counter(erlkoenig_nft_srv, ?INET, ?TABLE,
                                <<"counter_A">>),

    %% Phase 2: reload with counter_B instead
    ok = nfnl_server:apply_msgs(erlkoenig_nft_srv,
            [fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
             fun(S) -> nft_delete:table(?INET, ?TABLE, S) end,
             fun(S) -> nft_table:add(?INET, ?TABLE, S) end,
             fun(S) -> nft_object:add_counter(?INET, ?TABLE,
                                              <<"counter_B">>, S) end]),

    %% counter_A must now be gone
    ?assertMatch({error, _},
                 nfnl_server:get_counter(erlkoenig_nft_srv, ?INET, ?TABLE,
                                         <<"counter_A">>)),
    %% counter_B must be present and fresh
    ?assertMatch({ok, #{packets := 0, bytes := 0}},
                 nfnl_server:get_counter(erlkoenig_nft_srv, ?INET, ?TABLE,
                                         <<"counter_B">>)).
