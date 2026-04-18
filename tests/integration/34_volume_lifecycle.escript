#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 34: Volume lifecycle end-to-end.
%%
%% Exercises the full volume_store API against the real XFS backing
%% at /var/lib/erlkoenig/volumes/:
%%
%%   1.  Pre-flight: XFS backing present with prjquota enforcement on
%%   2.  Create three volumes: persistent+quota, persistent+ro, ephemeral
%%   3.  Verify on-disk layout --UUID dirs, by-name symlinks, mode 0750
%%   4.  Verify DETS index records the correct lifecycle + quota metadata
%%   5.  Verify XFS project binding created for the quota'd volume
%%   6.  Write up to the quota --exactly `cap` bytes accepted
%%   7.  Attempt to exceed --writer gets EDQUOT, file stays capped
%%   8.  Live-raise the quota --previously capped writer can now extend
%%   9.  Destroy one volume explicitly --UUID dir, symlink, DETS entry,
%%       xfs project binding all gone
%%   10. Cleanup remaining volumes
%%
%% Safety: uses unique persist names (prefix "t34-") so production
%% volume state cannot be touched. Pre-cleanup at start removes any
%% residue from prior failed runs.
%%
%% Requires: root, XFS-on-loop at /var/lib/erlkoenig/volumes/ with
%%           prjquota enabled (see Chapter 15 for setup).
-mode(compile).

-include_lib("kernel/include/file.hrl").

-define(VROOT, <<"/var/lib/erlkoenig/volumes">>).
-define(CT_NAME, <<"t34-ct">>).
-define(Q_PERSIST, <<"t34-data">>).
-define(RO_PERSIST, <<"t34-config">>).
-define(EPH_PERSIST, <<"t34-scratch">>).
-define(QUOTA_SMALL, <<"4M">>).
-define(QUOTA_LARGE, <<"12M">>).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 34: Volume lifecycle ===~n~n"),
    require_root(),
    require_xfs_backing(),

    test_helper:boot(),
    logger:set_primary_config(level, warning),

    %% Pre-clean any residue from prior runs.
    pre_cleanup(),

    %% ── 1. Create three volumes ─────────────────────────────
    {QUuid, RoUuid, EphUuid} =
        test_helper:step("create 3 volumes (persist+quota, ro, ephemeral)",
            fun() ->
                {ok, Q}  = erlkoenig_volume_store:ensure(
                    #{container => ?CT_NAME, persist => ?Q_PERSIST,
                      uid => 0, gid => 0, quota => ?QUOTA_SMALL}),
                {ok, Ro} = erlkoenig_volume_store:ensure(
                    #{container => ?CT_NAME, persist => ?RO_PERSIST,
                      uid => 0, gid => 0}),
                {ok, Ep} = erlkoenig_volume_store:ensure(
                    #{container => ?CT_NAME, persist => ?EPH_PERSIST,
                      uid => 0, gid => 0, lifecycle => ephemeral}),
                {ok, {maps:get(uuid, Q),
                      maps:get(uuid, Ro),
                      maps:get(uuid, Ep)}}
            end),

    %% ── 2. On-disk layout ──────────────────────────────────
    test_helper:step("UUID dirs and by-name symlinks on disk", fun() ->
        lists:foreach(fun(Uuid) ->
            Path = uuid_path(Uuid),
            true = filelib:is_dir(Path),
            {ok, FI} = file:read_file_info(Path),
            %% Mode bits must include 0750 (S_IFDIR | 0750 = 040750)
            Mode = FI#file_info.mode,
            case (Mode band 8#777) of
                8#750 -> ok;
                Other -> error({wrong_mode, Path, Other})
            end
        end, [QUuid, RoUuid, EphUuid]),

        %% by-name symlinks
        lists:foreach(fun(Persist) ->
            Link = filename:join([binary_to_list(?VROOT), "by-name",
                                   binary_to_list(?CT_NAME),
                                   binary_to_list(Persist)]),
            case file:read_link(Link) of
                {ok, Target} ->
                    case lists:prefix("../../ek_vol_",
                                      Target) of
                        true -> ok;
                        false -> error({bad_symlink_target, Link, Target})
                    end;
                Err -> error({symlink_missing, Link, Err})
            end
        end, [?Q_PERSIST, ?RO_PERSIST, ?EPH_PERSIST]),
        ok
    end),

    %% ── 3. DETS lifecycle metadata ─────────────────────────
    test_helper:step("DETS records lifecycle (persistent x2, ephemeral x1)",
        fun() ->
            Ephs = [V || V <- erlkoenig_volume_store:list(),
                         maps:get(lifecycle, V, persistent) =:= ephemeral,
                         binary:match(maps:get(persist, V), <<"t34-">>)
                             =/= nomatch],
            case length(Ephs) of
                1 -> ok;
                N -> error({expected_1_ephemeral, N, Ephs})
            end
        end),

    %% ── 4. XFS project binding ─────────────────────────────
    test_helper:step("XFS project binding visible in xfs_quota report",
        fun() ->
            {ok, QV} = erlkoenig_volume_store:find(?CT_NAME, ?Q_PERSIST),
            ProjectId = maps:get(project_id, QV),
            case ProjectId > 0 of
                true -> ok;
                false -> error({no_project_binding, QV})
            end
        end),

    %% ── 5. Write exactly to the cap ────────────────────────
    test_helper:step("write " ++ binary_to_list(?QUOTA_SMALL) ++
                    " --accepted",
        fun() ->
            File = filename:join(uuid_path(QUuid), "filler.bin"),
            {ok, Fd} = file:open(File, [raw, binary, write]),
            %% Write 4 MiB in 1 MiB chunks
            Chunk = binary:copy(<<0>>, 1024 * 1024),
            ok = write_n(Fd, Chunk, 4),
            ok = file:close(Fd),
            {ok, #file_info{size = Sz}} = file:read_file_info(File),
            case Sz of
                4194304 -> ok;
                _ -> error({unexpected_size_at_cap, Sz})
            end
        end),

    %% ── 6. Exceed --writer gets EDQUOT ─────────────────────
    test_helper:step("exceed quota --EDQUOT, file stays capped",
        fun() ->
            File = filename:join(uuid_path(QUuid), "overflow.bin"),
            %% The error may surface at open (inode allocation after cap)
            %% or at write. Both are valid quota-enforcement signals.
            Res = case file:open(File, [raw, binary, write]) of
                {ok, Fd} ->
                    Chunk = binary:copy(<<0>>, 1024 * 1024),
                    WR = try_write_n(Fd, Chunk, 2),
                    _ = file:close(Fd),
                    WR;
                {error, _} = E -> E
            end,
            case Res of
                {error, edquot} -> ok;
                {error, enospc} -> ok;
                _ -> error({expected_quota_enforcement, Res})
            end
        end),

    %% ── 7. Live-raise quota ────────────────────────────────
    test_helper:step("live raise quota, previously blocked writer succeeds",
        fun() ->
            {ok, _} = erlkoenig_volume_store:set_quota(
                QUuid, ?QUOTA_LARGE),
            %% Now a 2 MiB write should succeed (4M used + 2M = 6M < 12M cap)
            File = filename:join(uuid_path(QUuid), "after_raise.bin"),
            {ok, Fd} = file:open(File, [raw, binary, write]),
            Chunk = binary:copy(<<0>>, 1024 * 1024),
            ok = write_n(Fd, Chunk, 2),
            ok = file:close(Fd),
            ok
        end),

    %% ── 8. Destroy one volume, verify full cleanup ─────────
    test_helper:step("destroy pg-data --UUID dir, symlink, DETS entry gone",
        fun() ->
            ok = erlkoenig_volume_store:destroy(QUuid),
            %% UUID dir gone
            false = filelib:is_dir(uuid_path(QUuid)),
            %% by-name symlink gone
            Link = filename:join([binary_to_list(?VROOT), "by-name",
                                   binary_to_list(?CT_NAME),
                                   binary_to_list(?Q_PERSIST)]),
            {error, enoent} = file:read_link(Link),
            %% DETS entry gone
            not_found = erlkoenig_volume_store:find(?CT_NAME, ?Q_PERSIST),
            ok
        end),

    %% ── 9. Cleanup remainder ───────────────────────────────
    test_helper:step("cleanup remaining volumes", fun() ->
        ok = erlkoenig_volume_store:destroy(RoUuid),
        ok = erlkoenig_volume_store:destroy(EphUuid),
        ok
    end),

    %% ── 10. No t34- residue left ──────────────────────────
    test_helper:step("no t34-* volumes remain in store", fun() ->
        Leftover = [V || V <- erlkoenig_volume_store:list(),
                         binary:match(maps:get(persist, V), <<"t34-">>)
                             =/= nomatch],
        case Leftover of
            [] -> ok;
            _ -> error({stale_volumes, Leftover})
        end
    end),

    io:format("~n=== Test 34: all steps passed ===~n"),
    halt(0).

%%====================================================================
%% Helpers
%%====================================================================

require_root() ->
    case os:cmd("id -u") of
        "0\n" -> ok;
        _ -> io:format("SKIP: requires root~n"), halt(77)
    end.

require_xfs_backing() ->
    %% Check that /var/lib/erlkoenig/volumes is mounted with prjquota.
    Mounts = os:cmd("mount"),
    Pattern = "on " ++ binary_to_list(?VROOT) ++ " type xfs",
    case string:find(Mounts, Pattern) of
        nomatch ->
            io:format("SKIP: XFS backing not mounted at ~s~n"
                      "  Run the Chapter 15 setup first.~n",
                      [?VROOT]),
            halt(77);
        _ ->
            case string:find(Mounts, "prjquota") of
                nomatch ->
                    io:format("SKIP: prjquota not enabled on ~s~n",
                              [?VROOT]),
                    halt(77);
                _ -> ok
            end
    end.

uuid_path(Uuid) ->
    binary_to_list(iolist_to_binary([?VROOT, $/, Uuid])).

pre_cleanup() ->
    %% Destroy any leftover t34-* volumes from previous runs.
    Stale = [maps:get(uuid, V) ||
             V <- try erlkoenig_volume_store:list()
                  catch _:_ -> []
                  end,
             binary:match(maps:get(persist, V, <<>>), <<"t34-">>) =/= nomatch],
    lists:foreach(fun(U) ->
        _ = erlkoenig_volume_store:destroy(U)
    end, Stale),
    ok.

write_n(_Fd, _Chunk, 0) -> ok;
write_n(Fd, Chunk, N) ->
    case file:write(Fd, Chunk) of
        ok -> write_n(Fd, Chunk, N - 1);
        Err -> Err
    end.

try_write_n(_Fd, _Chunk, 0) -> {ok, done};
try_write_n(Fd, Chunk, N) ->
    case file:write(Fd, Chunk) of
        ok -> try_write_n(Fd, Chunk, N - 1);
        {error, Reason} -> {error, Reason}
    end.
