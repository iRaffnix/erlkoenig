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

-module(erlkoenig_recovery).
-moduledoc """
Boot-time container recovery.

Runs at application start, reads the DETS table, finds
still-running containers (by checking /proc/<pid>), and
reconnects to them via erlkoenig_ct:start_recovering/2.

Port-mode containers cannot survive a BEAM crash (pipes break),
so they are always cleaned up.
""".

-export([recover/0, migration_needed/2]).

-doc """
Recover containers from DETS state.

Returns {ok, Results} where Results is a list of {Id, Status} tuples.
Status is one of: recovered, dead, {error, Reason}.
""".
-spec recover() -> {ok, [{binary(), recovered | dead | {error, term()}}]}.
recover() ->
    Containers = erlkoenig_node_state:all_containers(),
    case Containers of
        [] ->
            logger:info("Recovery: no containers in DETS"),
            {ok, []};
        _ ->
            logger:info("Recovery: found ~p containers in DETS",
                        [length(Containers)]),
            Results = lists:map(fun({Id, Info}) ->
                try
                    recover_one(Id, Info)
                catch
                    Class:Reason:Stack ->
                        logger:error("Recovery failed for ~s: ~p:~p~n~p",
                                     [Id, Class, Reason, Stack]),
                        {Id, {error, {Class, Reason}}}
                end
            end, Containers),
            Recovered = length([ok || {_, recovered} <- Results]),
            Dead = length([ok || {_, dead} <- Results]),
            Failed = length(Results) - Recovered - Dead,
            logger:info("Recovery complete: ~p recovered, ~p dead, ~p failed",
                        [Recovered, Dead, Failed]),
            {ok, Results}
    end.

-doc """
Pure decision function for cgroup migration.

Compares the old path (from DETS, binary) with the new path (from
erlkoenig_cgroup:path/1, string) and returns `migrate` or `ok`.
Exported for testability.
""".
-spec migration_needed(binary(), string()) -> migrate | ok.
migration_needed(OldPathBin, NewPath) ->
    case binary_to_list(OldPathBin) =:= NewPath of
        true  -> ok;
        false -> migrate
    end.

%%====================================================================
%% Internal
%%====================================================================

-spec recover_one(binary(), map()) -> {binary(), recovered | dead | {error, term()}}.
recover_one(Id, #{os_pid := Pid} = Info) ->
    case is_process_alive_os(Pid) of
        true ->
            %% C-Runtime lives! Try to recover.
            Info1 = verify_infrastructure(Id, Info),
            %% Start gen_statem in recovering state
            case erlkoenig_ct:start_recovering(Id, Info1) of
                {ok, _StateMPid} ->
                    {Id, recovered};
                {error, Reason} ->
                    logger:error("Failed to start recovering statem for ~s: ~p",
                                 [Id, Reason]),
                    {Id, {error, Reason}}
            end;
        false ->
            %% C-Runtime is dead. Clean up.
            cleanup_dead(Id, Info),
            {Id, dead}
    end;
recover_one(Id, Info) ->
    cleanup_dead(Id, Info),
    {Id, dead}.

-doc "Check if an OS process is still alive by probing /proc/<pid>.".
-spec is_process_alive_os(integer()) -> boolean().
is_process_alive_os(Pid) when is_integer(Pid), Pid > 0 ->
    ProcPath = "/proc/" ++ integer_to_list(Pid),
    filelib:is_dir(ProcPath);
is_process_alive_os(_) ->
    false.

-doc "Verify that kernel resources still exist for a container.".
-spec verify_infrastructure(binary(), map()) -> map().
verify_infrastructure(Id, Info) ->
    verify_cgroup(Info),
    Info1 = maybe_migrate_cgroup(Id, Info),
    verify_network(Info1),
    rebuild_firewall(Id, Info1),
    Info1.

-spec verify_cgroup(map()) -> ok.
verify_cgroup(#{cgroup := CgroupPath}) ->
    case filelib:is_dir(binary_to_list(CgroupPath)) of
        true -> ok;
        false ->
            logger:warning("Cgroup ~s missing (topology migration or OS reboot)",
                           [CgroupPath]),
            ok
    end;
verify_cgroup(_) -> ok.

-doc """
Migrate cgroup path if DETS has an old-style path.

Compares the path stored in DETS with the current path from
erlkoenig_cgroup:path/1. If they differ, creates the new cgroup,
attaches the process, and explicitly persists to DETS.
""".
-spec maybe_migrate_cgroup(binary(), map()) -> map().
maybe_migrate_cgroup(Id, #{os_pid := OsPid, cgroup := OldPath} = Info) ->
    {ok, NewPath} = erlkoenig_cgroup:path(Id),
    case migration_needed(OldPath, NewPath) of
        ok ->
            Info;
        migrate ->
            ok = erlkoenig_cgroup:create(Id),
            ok = erlkoenig_cgroup:attach(Id, OsPid),
            NewPathBin = list_to_binary(NewPath),
            %% Explicitly persist to DETS — do not rely on implicit
            %% dets_register later. Recovery reattaches the container
            %% but does not go through the fresh start path.
            Info1 = Info#{cgroup := NewPathBin},
            erlkoenig_node_state:update_container(Id, Info1),
            logger:info("Migrated container ~s cgroup ~s -> ~s (persisted to DETS)",
                        [Id, OldPath, NewPath]),
            Info1
    end;
maybe_migrate_cgroup(_Id, Info) ->
    Info.

-spec verify_network(map()) -> ok.
verify_network(#{veth_host := Veth}) ->
    VethPath = "/sys/class/net/" ++ binary_to_list(Veth),
    case filelib:is_dir(VethPath) of
        true -> ok;
        false ->
            logger:warning("veth ~s missing", [Veth]),
            ok
    end;
verify_network(_) -> ok.

-spec rebuild_firewall(binary(), map()) -> ok.
rebuild_firewall(_Id, #{config := _Config}) ->
    %% Placeholder: full implementation in WP-CR6.
    %% erlkoenig_firewall_nft:add_container(Id, ...) will be called here.
    ok;
rebuild_firewall(_, _) -> ok.

-doc "Clean up resources for a dead container.".
-spec cleanup_dead(binary(), map()) -> ok.
cleanup_dead(Id, Info) ->
    logger:info("Cleaning up dead container ~s", [Id]),

    %% Clean up cgroup — try old path from DETS (may fail if not empty — that's ok)
    _ = case maps:get(cgroup, Info, undefined) of
        undefined -> ok;
        CgroupPath -> file:del_dir(binary_to_list(CgroupPath))
    end,

    %% Also try destroying via the new topology path.
    %% During migration, the old DETS path and the current path may differ.
    %% Best-effort: cgroup gen_server may not be running (e.g. unit tests).
    _ = catch erlkoenig_cgroup:destroy(Id),

    %% Clean up socket file
    _ = case maps:get(socket_path, Info, undefined) of
        undefined -> ok;
        SocketPath -> file:delete(binary_to_list(SocketPath))
    end,

    %% Remove DETS entry
    erlkoenig_node_state:unregister_container(Id),
    ok.
