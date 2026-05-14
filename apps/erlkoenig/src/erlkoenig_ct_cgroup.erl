%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_cgroup).
-moduledoc """
Cgroup v2 lifecycle for a single container.

Owns the `create → attach → set_limits' chain for the cgroup
slice, plus the two eBPF programs that run on top of it
(device filter, metrics), plus the top-level
`do_container_setup/1' orchestrator that runs immediately after
the C runtime reports the container PID.

Paired teardown lives in `handle_check_restart' via
`destroy_cgroup/1' — kept here so create/destroy sit together.

Separated from `erlkoenig_ct_net' because network and cgroup
are genuinely distinct subsystems with different failure modes.
The state machine orchestrates both.
""".

-include("erlkoenig_ct_state.hrl").
-include("erlkoenig_error.hrl").

-export([
    do_container_setup/1,
    setup_cgroup/3,
    destroy_cgroup/1,
    setup_device_filter/2,
    setup_metrics/2
]).

-spec do_container_setup(#ct_data{}) ->
    {next_state, atom(), #ct_data{}}.
do_container_setup(#ct_data{id = Id, os_pid = OsPid,
                            limits = Limits} = Data) ->
    %% Step 1: cgroup (before GO so the app process inherits it).
    case setup_cgroup(Id, OsPid, Limits) of
        ok ->
            do_container_setup_after_cgroup(true, Data);
        {error, CgReason} ->
            case erlkoenig_cgroup:production_mode() of
                true ->
                    logger:error("container ~s: cgroup setup failed in "
                                 "production mode: ~p",
                                 [Id, CgReason]),
                    Err = ?EK_ERROR_S(critical, ct, cgroup_setup_failed,
                                      "container cgroup setup failed",
                                      #{reason => CgReason}),
                    erlkoenig_error:emit(Err, Id),
                    {next_state, failed,
                     Data#ct_data{error_reason = Err}};
                false ->
                    logger:warning("container ~s: cgroup setup failed: ~p "
                                   "(development mode: continuing without limits)",
                                   [Id, CgReason]),
                    do_container_setup_after_cgroup(false, Data)
            end
    end.

-spec do_container_setup_after_cgroup(boolean(), #ct_data{}) ->
    {next_state, atom(), #ct_data{}}.
do_container_setup_after_cgroup(HasCgroup, #ct_data{id = Id} = Data) ->
    %% Step 1b: eBPF device filter (defense-in-depth).
    %% Restricts which devices the container can access at kernel level,
    %% even if it somehow escapes the filesystem isolation.
    case HasCgroup of
        true ->
            setup_device_filter(Data, Id),
            case maps:get(observe, Data#ct_data.extra_opts, undefined) of
                undefined -> ok;
                _Metrics  ->
                    setup_metrics(Data, Id),
                    %% Register policy if defined
                    case maps:get(policy, Data#ct_data.extra_opts, undefined) of
                        undefined -> ok;
                        Policy    -> erlkoenig_policy:register_policy(Id, Policy)
                    end
            end;
        false ->
            ok
    end,
    %% Step 2: FUSE rootfs (if rootfs config present in extra_opts).
    case erlkoenig_ct_volume:maybe_setup_rootfs(Data) of
        {ok, Data2} ->
            %% Step 3: network + files + GO.
            %% Note: uid_map/gid_map is written by the C runtime (erlkoenig_ns.c)
            %% immediately after clone, before replying with container_pid.
            %% By the time we get here, the child already has capabilities.
            erlkoenig_ct_net:do_container_net_setup(Data2);
        {error, FuseReason} ->
            _ = erlkoenig_cgroup:destroy(Id),
            Err = ?EK_ERROR(ct, rootfs_setup_failed,
                            "container rootfs setup failed",
                            #{reason => FuseReason}),
            {next_state, failed,
             Data#ct_data{error_reason = Err}}
    end.

-spec destroy_cgroup(#ct_data{}) -> ok | {error, term()}.
destroy_cgroup(#ct_data{id = Id}) ->
    erlkoenig_cgroup:destroy(Id).

-spec setup_cgroup(binary(), non_neg_integer(), map()) -> ok | {error, term()}.
setup_cgroup(Id, OsPid, Limits) ->
    maybe
        %% cgroup may already exist (pre-created in creating_do_spawn
        %% so erlkoenig_rt starts in containers/ not beam/).
        %% create is idempotent — returns ok if already exists.
        ok ?= erlkoenig_cgroup:create(Id),
        %% Attach the container's PID. If erlkoenig_rt already wrote
        %% itself via echo $$ > cgroup.procs, this is a no-op (PID
        %% is already in the right cgroup). But the child PID from
        %% clone/fork may be different, so always attach.
        ok ?= erlkoenig_cgroup:attach(Id, OsPid),
        %% The `?=' here is deliberate: without it, set_limits errors
        %% would flow through as the maybe's return value but would
        %% skip the else-branch's destroy, leaving a half-configured
        %% cgroup behind that the caller thinks doesn't exist
        %% (HasCgroup=false). Parallel paths would diverge from the
        %% create/attach-failure cleanup.
        ok ?= case map_size(Limits) =:= 0 of
            true  -> ok;
            false -> erlkoenig_cgroup:set_limits(Id, Limits)
        end
    else
        {error, _} = Err ->
            _ = erlkoenig_cgroup:destroy(Id),
            Err
    end.

-spec setup_device_filter(#ct_data{}, binary()) -> ok.
setup_device_filter(Data, Id) ->
    case erlkoenig_cgroup:path(Id) of
        {ok, CgroupPath} ->
            CgroupBin = list_to_binary(CgroupPath),
            Cmd = erlkoenig_proto:encode_cmd_device_filter(CgroupBin),
            case erlkoenig_ct_rt:sync_rt_command(Data, Cmd, 5000) of
                {ok, Reply} ->
                    erlkoenig_ct_rt:handle_setup_reply(Reply, Id, "device filter");
                {error, Reason} ->
                    logger:warning("container ~s: device filter failed: ~p",
                                   [Id, Reason])
            end;
        {error, _} ->
            ok
    end,
    ok.

-spec setup_metrics(#ct_data{}, binary()) -> ok.
setup_metrics(Data, Id) ->
    case erlkoenig_cgroup:path(Id) of
        {ok, CgroupPath} ->
            CgroupBin = list_to_binary(CgroupPath),
            Cmd = erlkoenig_proto:encode_cmd_metrics_start(CgroupBin),
            case erlkoenig_ct_rt:sync_rt_command(Data, Cmd, 5000) of
                {ok, Reply} ->
                    erlkoenig_ct_rt:handle_setup_reply(Reply, Id, "eBPF metrics");
                {error, Reason} ->
                    logger:warning("container ~s: eBPF metrics failed: ~p",
                                   [Id, Reason])
            end;
        {error, _} ->
            ok
    end,
    ok.
