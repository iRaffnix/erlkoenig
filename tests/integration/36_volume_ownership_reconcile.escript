#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 36: Volume ownership is reconciled on ensure when uid/gid change.
%%
%% Regression test for the chown-skip bug (2026-04-17):
%%   do_ensure/1 skipped ensure_dir (which chowns) when the volume
%%   already existed in DETS. That meant an operator changing `uid:`
%%   in a stack file and re-running `ek up` wouldn't update the bind-
%%   mount source ownership. Container running as the new UID couldn't
%%   write its own persistent data.
%%
%% Fix: maybe_reconcile_ownership/3 is now called for existing volumes.
%% Plus ensure_dir's eexist path does the same check (recovery scenario).
%%
%% This test verifies the round-trip:
%%   1. ensure(uid=0) on a fresh persist key  -> dir 0:0
%%   2. ensure(uid=70) on same key            -> dir flipped to 70:70
%%   3. ensure(uid=70) again                  -> still 70:70 (idempotent)
%%   4. ensure(uid=99) on same key            -> dir flipped to 99:99
-mode(compile).

-include_lib("kernel/include/file.hrl").

-define(CT, <<"t36-ct">>).
-define(P, <<"t36-p">>).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 36: volume ownership reconcile ===~n~n"),

    require_root(),

    test_helper:boot(),
    logger:set_primary_config(level, warning),

    %% Pre-clean any leftover t36-* volumes
    cleanup_t36(),

    Uuid = test_helper:step("ensure(uid=0) creates fresh volume", fun() ->
        {ok, V} = erlkoenig_volume_store:ensure(#{
            container => ?CT, persist => ?P,
            uid => 0, gid => 0}),
        {ok, maps:get(uuid, V)}
    end),

    HostPath = uuid_path(Uuid),

    test_helper:step("step 1: uid=0 gid=0 on disk", fun() ->
        assert_ownership(HostPath, 0, 0)
    end),

    test_helper:step("ensure(uid=70) re-ensures ownership", fun() ->
        {ok, _} = erlkoenig_volume_store:ensure(#{
            container => ?CT, persist => ?P,
            uid => 70, gid => 70}),
        assert_ownership(HostPath, 70, 70)
    end),

    test_helper:step("ensure(uid=70) again is idempotent", fun() ->
        {ok, _} = erlkoenig_volume_store:ensure(#{
            container => ?CT, persist => ?P,
            uid => 70, gid => 70}),
        assert_ownership(HostPath, 70, 70)
    end),

    test_helper:step("ensure(uid=99) flips ownership again", fun() ->
        {ok, _} = erlkoenig_volume_store:ensure(#{
            container => ?CT, persist => ?P,
            uid => 99, gid => 99}),
        assert_ownership(HostPath, 99, 99)
    end),

    test_helper:step("cleanup", fun() ->
        cleanup_t36()
    end),

    io:format("~n=== Test 36 passed ===~n"),
    halt(0).

%%====================================================================
%% Helpers
%%====================================================================

require_root() ->
    case os:cmd("id -u") of
        "0\n" -> ok;
        _ -> io:format("SKIP: requires root~n"), halt(77)
    end.

uuid_path(Uuid) ->
    binary_to_list(iolist_to_binary([
        <<"/var/lib/erlkoenig/volumes/">>, Uuid])).

assert_ownership(Path, ExpectedUid, ExpectedGid) ->
    case file:read_file_info(Path) of
        {ok, #file_info{uid = ExpectedUid, gid = ExpectedGid}} ->
            ok;
        {ok, FI} ->
            error({ownership_mismatch, Path,
                   {expected, ExpectedUid, ExpectedGid},
                   {actual, FI#file_info.uid, FI#file_info.gid}});
        Err ->
            error({stat_failed, Path, Err})
    end.

cleanup_t36() ->
    Stale = [maps:get(uuid, V) ||
             V <- try erlkoenig_volume_store:list() catch _:_ -> [] end,
             binary:match(maps:get(persist, V, <<>>), <<"t36-">>) =/= nomatch],
    lists:foreach(fun(U) ->
        _ = erlkoenig_volume_store:destroy(U)
    end, Stale),
    ok.
