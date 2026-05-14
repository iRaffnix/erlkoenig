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

-module(erlkoenig_ct).
-moduledoc """
Container lifecycle as gen_statem.

One gen_statem per container. Manages the C runtime (erlkoenig_rt)
via Unix Domain Socket at /run/erlkoenig/containers/<id>.sock.
Drives the SPAWN -> GO -> EXITED sequence, handles kill/stop.

States:
  creating        -> Socket opened, SPAWN sent
  namespace_ready -> Got container PID, ready for network setup
  starting        -> GO sent, waiting for ack
  running         -> Container executing
  stopping        -> SIGTERM sent, waiting for exit
  stopped         -> Container exited, cleanup done
  restarting      -> Backoff before restart
  recovering      -> Reconnecting to still-running container after crash
  disconnected    -> Socket lost, attempting reconnect
  failed          -> Error occurred, stays alive for inspection
""".

-behaviour(gen_statem).

-include("erlkoenig_error.hrl").

%% API
-export([start_link/2,
         start_recovering/2,
         go/1,
         stop_container/1,
         kill/2,
         get_info/1,
         get_info/2,
         dns_filter_state/1,
         list/0,
         attach/2,
         send_input/2,
         resize/3,
         forget_restart_count/1]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3]).

-export([creating/3, namespace_ready/3, starting/3,
         running/3, stopping/3, stopped/3, restarting/3,
         recovering/3, disconnected/3, failed/3]).

-ifdef(TEST).
-export([should_record_terminal_crash/2, restart_cleanup_result/3]).
-endif.

%% Restart policy: controls if and how a container is restarted
%% after exit or failure.
%%
%%   no_restart       - never restart (default)
%%   always           - restart on any exit, unlimited
%%   on_failure       - restart on non-zero exit / signal, unlimited
%%   {always, N}      - restart on any exit, max N attempts
%%   {on_failure, N}  - restart on non-zero exit / signal, max N attempts
%%
%% Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s (cap).
%% The Erlang PID and container IP stay stable across restarts.

%% The `#ct_data{}' record lives in `erlkoenig_ct_state.hrl' so the
%% extracted helper modules can match on the same shape without
%% accessor round-trips. Include here so every state-callback clause
%% keeps pattern-matching on fields exactly as before.
-include("erlkoenig_ct_state.hrl").

-define(SPAWN_TIMEOUT, application:get_env(erlkoenig, spawn_timeout, 30_000)).
-define(GO_TIMEOUT,    application:get_env(erlkoenig, go_timeout,    10_000)).
-define(STOP_TIMEOUT,  application:get_env(erlkoenig, stop_timeout,   5_000)).
-define(RECONNECT_MAX_ATTEMPTS,
        application:get_env(erlkoenig, reconnect_max_attempts, 30)).

%% =================================================================
%% API
%% =================================================================

-spec start_link(binary(), map()) -> gen_statem:start_ret().
start_link(BinaryPath, Opts) ->
    gen_statem:start_link(?MODULE, {normal, BinaryPath, Opts}, []).

-doc "Start a gen_statem in recovering state for crash recovery.".
%% Called by the recovery module (WP-CR4) when a still-running container
%% is found after a BEAM restart.
-spec start_recovering(binary(), map()) -> gen_statem:start_ret().
start_recovering(ContainerId, RecoveryInfo) ->
    gen_statem:start_link(?MODULE, {recover, ContainerId, RecoveryInfo}, []).

-spec go(pid()) -> ok | {error, term()}.
go(Pid) ->
    gen_statem:call(Pid, go).

-spec stop_container(pid()) -> ok | {error, term()}.
stop_container(Pid) ->
    gen_statem:call(Pid, stop_container).

-spec kill(pid(), non_neg_integer()) -> ok | {error, term()}.
kill(Pid, Signal) ->
    gen_statem:call(Pid, {kill, Signal}).

-spec get_info(pid()) -> map().
get_info(Pid) ->
    gen_statem:call(Pid, get_info).

-spec get_info(pid(), timeout()) -> map().
get_info(Pid, Timeout) ->
    gen_statem:call(Pid, get_info, Timeout).

%% Narrow recovery read: returns the container's IP + declared
%% dns_allowlist, or `undefined` if the container does not have
%% one. Used by `erlkoenig_dns_filter` after a restart to reseed
%% its ETS without going through the broader `get_info` API and
%% without needing a new gen_statem call in every lifecycle state.
%%
%% Implementation uses `sys:get_state` with a short timeout. This
%% is deliberately "peek into the gen_statem's guts" territory —
%% acceptable because the shape of `#ct_data{}` is stable within
%% the app and this path is only used during supervisor-initiated
%% filter recovery, not in steady-state hot code.
-spec dns_filter_state(pid()) ->
    {inet:ip4_address(), [binary()]} | undefined.
dns_filter_state(Pid) ->
    try sys:get_state(Pid, 250) of
        {running, #ct_data{ip = Ip,
                            dns_allowlist = Hosts}}
          when is_list(Hosts), Hosts =/= [], Ip =/= undefined ->
            {Ip, Hosts};
        _ -> undefined
    catch
        _:_ -> undefined
    end.

%% Return info maps for every container known to the node (including
%% terminal stopped/failed ones, kept alive for post-mortem). Mirrors
%% `erlkoenig:list/0` but is exported directly so operator tooling
%% doesn't have to know about the pg layer.
-spec list() -> [map()].
list() ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts_all)
           catch _:_ -> []
           end,
    lists:filtermap(fun(Pid) ->
        try {true, get_info(Pid)}
        catch _:_ -> false
        end
    end, Pids).

%% Drop the persistent restart counter for a container name. Called from
%% erlkoenig_config when a name leaves the declared set — after that,
%% the next spawn with the same name starts counting from zero again.
-spec forget_restart_count(binary() | undefined) -> ok.
forget_restart_count(undefined) -> ok;
forget_restart_count(Name) when is_binary(Name) ->
    _ = persistent_term:erase({?MODULE, restart_count, Name}),
    ok.

%% Internal: read-and-bump the persistent restart counter for this name.
%% First spawn of a name → 0 (stored). Every later spawn under the same
%% name → previous + 1 (stored and returned). A nameless container (for
%% ad-hoc spawns from the REPL) bypasses persistence entirely.
-spec initial_restart_count(binary() | undefined) -> non_neg_integer().
initial_restart_count(undefined) -> 0;
initial_restart_count(Name) when is_binary(Name) ->
    Key = {?MODULE, restart_count, Name},
    case persistent_term:get(Key, undefined) of
        undefined ->
            ok = persistent_term:put(Key, 0),
            0;
        Prior ->
            Next = Prior + 1,
            ok = persistent_term:put(Key, Next),
            Next
    end.

-spec persist_restart_count(binary() | undefined, non_neg_integer()) -> ok.
persist_restart_count(undefined, _) -> ok;
persist_restart_count(Name, Count) when is_binary(Name) ->
    ok = persistent_term:put({?MODULE, restart_count, Name}, Count),
    ok.

-spec attach(pid(), pid()) -> ok | {error, term()}.
attach(Pid, OutputPid) ->
    gen_statem:call(Pid, {attach, OutputPid}).

-spec send_input(pid(), binary()) -> ok.
send_input(Pid, Data) ->
    gen_statem:cast(Pid, {send_input, Data}).

-spec resize(pid(), non_neg_integer(), non_neg_integer()) -> ok | {error, term()}.
resize(Pid, Rows, Cols) ->
    gen_statem:call(Pid, {resize, Rows, Cols}).

%% =================================================================
%% gen_statem callbacks
%% =================================================================

callback_mode() -> [state_functions, state_enter].

init({normal, BinaryPath, Opts}) ->
    Id = make_id(),
    proc_lib:set_label({erlkoenig_ct, Id}),
    %% `erlkoenig_cts_all` tracks every live ct gen_statem regardless of
    %% lifecycle state, so operator-facing lookups (`ek ct list/inspect`)
    %% can still find a container after it transitioned to stopped or
    %% failed. The narrower `erlkoenig_cts` group is joined later in
    %% running(enter, _) and explicitly left on stopped/failed entry —
    %% it is the "currently running" set used by DNS filter, drift
    %% reconciler, force-stop, and zone-occupancy checks.
    pg:join(erlkoenig_pg, erlkoenig_cts_all, self()),
    Restart = erlkoenig_ct_opts:validate_restart(maps:get(restart, Opts, no_restart)),
    Name = maps:get(name, Opts, undefined),
    %% Restart counter survives gen_statem reincarnations (pod-supervisor
    %% respawn, drift-reconcile teardown/re-spawn) by living in
    %% persistent_term keyed by container name. A brand-new name starts
    %% at 0; every later init/1 under the same name bumps the stored
    %% count by one.
    InitRestartCount = initial_restart_count(Name),
    %% Pod-supervised containers have their IP pre-computed in
    %% `erlkoenig_config:flatten_containers` and baked into Opts.
    %% On supervisor-driven restart the SAME Opts are reused —
    %% including the old IP.  But the old IPVLAN slave in the dying
    %% container's netns still holds that IP on the parent dummy
    %% (kernel cleanup is asynchronous to gen_statem exit), so
    %% `ip addr add` on the new slave trips `EADDRINUSE (-98)`.
    %%
    %% Workaround: on ANY restart (restart_count > 0) of a
    %% pod-supervised container, drop the baked-in IP so
    %% `setup_container_net` allocates a fresh one from the zone
    %% pool.  The old IP will return via the cooldown + free-list
    %% once the kernel has reaped the old netns.
    PodSupervised = maps:get(pod_supervised, Opts, false),
    ForcedIp = maps:get(ip, Opts, undefined),
    InitIp =
        case {PodSupervised, InitRestartCount} of
            {true, N} when N > 0 ->
                logger:info("[erlkoenig_ct] pod-supervised ~p restart #~p — "
                            "dropping baked-in ip ~p for fresh pool alloc",
                            [Name, N, ForcedIp]),
                undefined;
            _ -> ForcedIp
        end,
    Data = #ct_data{
        id          = Id,
        binary_path = BinaryPath,
        args        = maps:get(args, Opts, []),
        env         = maps:get(env, Opts, []),
        uid         = maps:get(uid, Opts, 0),
        gid         = maps:get(gid, Opts, 0),
        ip          = InitIp,
        zone        = maps:get(zone, Opts, default),
        restart     = Restart,
        restart_count = InitRestartCount,
        limits      = maps:get(limits, Opts, #{}),
        seccomp     = erlkoenig_ct_opts:seccomp_profile_id(maps:get(seccomp, Opts, none)),
        caps_keep   = erlkoenig_ct_opts:caps_to_mask(maps:get(caps, Opts, [])),
        output      = maps:get(output, Opts, undefined),
        name        = Name,
        files       = maps:get(files, Opts, #{}),
        pty         = maps:get(pty, Opts, false),
        firewall    = maps:get(firewall, Opts, #{}),
        sig_path    = maps:get(sig_path, Opts, undefined),
        signature_required = maps:get(signature_required, Opts, false),
        volumes     = erlkoenig_ct_opts:merge_socket_mounts(
                        maps:get(volumes, Opts, []),
                        maps:get(socket_mounts, Opts, [])),
        requires    = maps:get(requires, Opts, []),
        dns_allowlist = maps:get(dns_allowlist, Opts, undefined),
        pod_supervised = maps:get(pod_supervised, Opts, false),
        publish     = maps:get(publish, Opts, []),
        stream      = maps:get(stream, Opts, undefined),
        extra_opts  = maps:without([args, env, uid, gid, ip, restart,
                                    limits, seccomp, caps, output, name,
                                    files, zone, pty, firewall, sig_path,
                                    signature_required, volumes, socket_mounts,
                                    requires, dns_allowlist,
                                    pod_supervised, publish, stream], Opts)
    },
    {ok, creating, Data};

init({recover, ContainerId, #{socket_path := SocketPath, os_pid := OsPid} = Info}) ->
    proc_lib:set_label({erlkoenig_ct, ContainerId}),
    %% See `init({normal, _, _})' for the rationale on `erlkoenig_cts_all'.
    pg:join(erlkoenig_pg, erlkoenig_cts_all, self()),
    process_flag(trap_exit, true),
    Config = maps:get(config, Info, #{}),
    Data = #ct_data{
        id          = ContainerId,
        binary_path = maps:get(binary_path, Info, <<>>),
        socket_path = SocketPath,
        os_pid      = OsPid,
        ip          = maps:get(ip, Config, undefined),
        zone        = maps:get(zone, Config, default),
        restart     = erlkoenig_ct_opts:validate_restart(maps:get(restart, Config, no_restart)),
        limits      = maps:get(limits, Config, #{}),
        seccomp     = erlkoenig_ct_opts:seccomp_profile_id(maps:get(seccomp, Config, none)),
        caps_keep   = erlkoenig_ct_opts:caps_to_mask(maps:get(caps, Config, [])),
        name        = maps:get(name, Config, undefined),
        firewall    = maps:get(firewall, Config, #{}),
        volumes     = maps:get(volumes, Config, []),
        extra_opts  = maps:get(extra_opts, Config, #{})
    },
    {ok, recovering, Data, [{state_timeout, 5000, recovery_timeout}]};

%% Backwards compatibility: old-style init tuple without 'normal' tag
init({BinaryPath, Opts}) when is_binary(BinaryPath), is_map(Opts) ->
    init({normal, BinaryPath, Opts}).

terminate(_Reason, _State, #ct_data{sock = Sock, socket_path = SockPath}) ->
    erlkoenig_ct_resources:safe_sock_close(Sock),
    erlkoenig_ct_resources:cleanup_socket_file(SockPath),
    ok.

%% =================================================================
%% creating - Open port, send SPAWN
%% =================================================================

creating(enter, _OldState, Data) ->
    %% state_enter cannot return {next_state, ...}.
    %% Send ourselves a message to trigger spawn asynchronously.
    self() ! do_spawn,
    {keep_state, Data};

creating(info, do_spawn, Data) ->
    Data2 = erlkoenig_ct_volume:resolve_volumes(Data),
    creating_do_spawn(Data2);

creating(info, {tcp, Sock, Reply}, #ct_data{sock = Sock,
                                             handshake = HS} = Data) ->
    creating_handle_rt_data(Reply, HS, Data);

creating(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    {next_state, failed,
     Data#ct_data{sock = undefined,
                  error_reason = ct_error(socket_closed,
                                          "runtime socket closed during create",
                                          #{phase => creating})}};

creating(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock} = Data) ->
    {next_state, failed,
     Data#ct_data{sock = undefined,
                  error_reason = ct_error(socket_error,
                                          "runtime socket errored during create",
                                          #{phase => creating, reason => Reason})}};

creating(state_timeout, spawn_timeout, Data) ->
    {next_state, failed,
     Data#ct_data{error_reason = ct_error(spawn_timeout,
                                          "container spawn timed out",
                                          #{timeout_ms => ?SPAWN_TIMEOUT})}};

creating({call, From}, get_info, Data) ->
    {keep_state_and_data,
     [{reply, From, erlkoenig_ct_info:build_info(creating, Data)}]};

creating({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]};

creating(info, {poll_stats, _, _}, _Data) -> keep_state_and_data;
creating(info, check_restart, _Data) -> keep_state_and_data.

creating_do_spawn(#ct_data{id = ContainerId,
                            binary_path = BinaryPath,
                            limits = Limits,
                            zone = Zone} = Data) ->
    %% Pre-spawn gates — both must pass before any expensive work
    %% (socket creation, namespace setup, nft installation).
    case erlkoenig_ct_security:resource_then_admission_then_quarantine(
           ContainerId, Limits, Zone, BinaryPath) of
        {ok, AdmissionToken} ->
            creating_do_spawn_gated(Data#ct_data{admission_token = AdmissionToken});
        {error, {resource_admission_denied, Reason}} ->
            logger:warning("container ~s: resource admission denied: ~p",
                           [ContainerId, Reason]),
            Err0 = ct_error(resource_admission_denied,
                            "resource admission denied",
                            #{zone => Zone, reason => Reason, limits => Limits}),
            Err = attach_container(Err0, ContainerId),
            erlkoenig_error:emit(Err),
            %% Hot path: keep the denial in the ETS ring so `ek
            %% admission denial <id>` can answer immediately without
            %% reading the audit file.
            erlkoenig_denial_log:record_denial(#{
                container_id => ContainerId,
                container_name => Data#ct_data.name,
                ts_ms => erlang:system_time(millisecond),
                zone => Zone,
                reason => Reason,
                limits => Limits
            }),
            %% Cold path: persist full evidence so the same lookup can
            %% replay denials after restart, when the ETS ring is gone.
            %% Include container_name so the audit-fallback lookup in
            %% `ek:admission_denial/1` can resolve the operator-typed
            %% friendly name (DSL-declared) as well as the generated
            %% container id.
            AuditDetails0 = #{zone => Zone,
                              reason => Reason,
                              limits => Limits},
            AuditDetails = case Data#ct_data.name of
                undefined -> AuditDetails0;
                CtName    -> AuditDetails0#{container_name => CtName}
            end,
            erlkoenig_audit:log(#{type => resource_admission_denied,
                                  subject => ContainerId,
                                  result => denied,
                                  details => AuditDetails}),
            {next_state, failed,
             Data#ct_data{error_reason = Err}};
        {error, admission_timeout} ->
            logger:warning("container ~s: admission gate timed out", [ContainerId]),
            Err0 = ct_error(admission_timeout,
                            "admission gate timed out",
                            #{zone => Zone}),
            Err = attach_container(Err0, ContainerId),
            erlkoenig_error:emit(Err),
            {next_state, failed,
             Data#ct_data{error_reason = Err}};
        {error, admission_queue_full} ->
            logger:warning("container ~s: admission queue full", [ContainerId]),
            Err0 = ct_error(admission_queue_full,
                            "admission queue is full",
                            #{zone => Zone}),
            Err = attach_container(Err0, ContainerId),
            erlkoenig_error:emit(Err),
            {next_state, failed,
             Data#ct_data{error_reason = Err}};
        {error, admission_unavailable} ->
            logger:error("container ~s: admission gate unavailable", [ContainerId]),
            Err0 = ct_error(admission_unavailable,
                            "admission gate unavailable",
                            #{zone => Zone}),
            Err = attach_container(Err0, ContainerId),
            erlkoenig_error:emit(Err),
            {next_state, failed,
             Data#ct_data{error_reason = Err}};
        {error, quarantine_unavailable} ->
            logger:error("container ~s: quarantine gate unavailable", [ContainerId]),
            Err0 = ct_error(quarantine_unavailable,
                            "quarantine gate unavailable",
                            #{zone => Zone}),
            Err = attach_container(Err0, ContainerId),
            erlkoenig_error:emit(Err),
            {next_state, failed,
             Data#ct_data{error_reason = Err}};
        {error, {quarantined, Hash, Since}} ->
            logger:warning("container ~s: binary quarantined (~s since ~p)",
                           [ContainerId, erlkoenig_ct_security:format_hash_prefix(Hash), Since]),
            Err0 = ?EK_ERROR(runtime, binary_quarantined,
                             "spawn refused by quarantine",
                             #{hash_prefix => erlkoenig_ct_security:format_hash_prefix(Hash),
                               since_ms => Since}),
            Err = attach_container(Err0, ContainerId),
            erlkoenig_error:emit(Err),
            {next_state, failed,
             Data#ct_data{error_reason = Err}}
    end.

creating_do_spawn_gated(#ct_data{id = ContainerId} = Data) ->
    SocketPath = erlkoenig_ct_rt:make_socket_path(ContainerId),
    ok = filelib:ensure_dir(binary_to_list(SocketPath)),
    %% Pre-create the container cgroup so the C runtime starts in it
    %% instead of the beam cgroup. This prevents erlkoenig_rt processes
    %% from counting against beam_memory_max.
    CgroupProcs = case erlkoenig_cgroup:ensure_container_dir(ContainerId) of
        {ok, ProcsPath} -> ProcsPath;
        {error, CgroupReason} ->
            case erlkoenig_cgroup:production_mode() of
                true ->
                    logger:error("container ~s: cgroup dir setup failed in "
                                 "production mode: ~p",
                                 [ContainerId, CgroupReason]),
                    Err = ct_error(cgroup_setup_failed,
                                   "container cgroup pre-spawn setup failed",
                                   #{reason => CgroupReason}),
                    erlkoenig_error:emit(Err, ContainerId),
                    {next_state, failed,
                     Data#ct_data{error_reason = Err}};
                false ->
                    logger:warning("container ~s: cgroup dir setup failed (~p), "
                                   "development mode: rt will start in beam cgroup",
                                   [ContainerId, CgroupReason]),
                    undefined
            end
    end,
    case CgroupProcs of
        {next_state, failed, _} = Failed ->
            Failed;
        _ ->
            creating_do_spawn_with_cgroup(Data, SocketPath, CgroupProcs)
    end.

creating_do_spawn_with_cgroup(#ct_data{id = ContainerId} = Data,
                              SocketPath,
                              CgroupProcs) ->
    %% Start C runtime via setsid in a background Erlang process.
    %% If cgroup is available, write the shell's PID into the container
    %% cgroup before exec — so erlkoenig_rt inherits it.
    RtBin = erlkoenig_ct_rt_discover:rt_path(),
    SockStr = binary_to_list(SocketPath),
    IdStr = binary_to_list(ContainerId),
    CgFlag = case CgroupProcs of
        undefined -> "";
        CgProcsPath -> " --cgroup " ++ CgProcsPath
    end,
    ShCmd = lists:flatten(io_lib:format(
        "exec setsid ~s --socket ~s --id ~s~s </dev/null 2>/dev/null",
        [RtBin, SockStr, IdStr, CgFlag])),
    erlang:spawn(fun() -> os:cmd(ShCmd) end),
    %% Wait for C runtime to bind the socket, then connect
    case erlkoenig_ct_rt:wait_and_connect(SocketPath, 10000) of
        {ok, Sock} ->
            ok = inet:setopts(Sock, [binary, {packet, 4}, {active, true}]),
            %% Protocol handshake via socket
            ok = gen_tcp:send(Sock, erlkoenig_proto:encode_handshake()),
            RtPid = erlkoenig_ct_rt:runtime_pid_from_cgroup(CgroupProcs),
            {keep_state, Data#ct_data{
                sock = Sock,
                socket_path = SocketPath,
                rt_pid = RtPid
            }, [{state_timeout, ?SPAWN_TIMEOUT, spawn_timeout}]};
        {error, Err} ->
            Err2 = ?EK_ERROR(runtime, socket_connect_failed,
                             "wait_and_connect to erlkoenig_rt socket",
                             #{socket_path => SocketPath, reason => Err,
                               timeout_ms  => 10000}),
            erlkoenig_error:emit(Err2, Data#ct_data.id),
            {next_state, failed,
             Data#ct_data{error_reason = Err2}}
    end.

creating_send_spawn(Data) ->
    DiskMB = erlkoenig_ct_opts:disk_limit_mb(Data#ct_data.limits),
    DnsIp  = erlkoenig_ct_net:effective_dns_ip(Data),
    Flags  = case Data#ct_data.pty of
                 true  -> erlkoenig_proto:spawn_flag_pty();
                 false -> 0
             end,
    %% Pass volumes through with their full DSL fields intact —
    %% erlkoenig_proto:encode_volume_tlv/1 runs resolve_volume/1 on
    %% each to pick up `opts:` strings and `read_only:` booleans.
    WireVolumes = Data#ct_data.volumes,
    ExtraOpts = Data#ct_data.extra_opts,
    SpawnOpts = #{
        path       => Data#ct_data.binary_path,
        args       => Data#ct_data.args,
        env        => Data#ct_data.env,
        uid        => Data#ct_data.uid,
        gid        => Data#ct_data.gid,
        seccomp    => Data#ct_data.seccomp,
        rootfs_mb  => DiskMB,
        caps_keep  => Data#ct_data.caps_keep,
        dns_ip     => DnsIp,
        flags      => Flags,
        volumes    => WireVolumes,
        image_path => maps:get(image_path, ExtraOpts, <<>>)
    },
    Cmd = erlkoenig_proto:encode_cmd_spawn(SpawnOpts),
    %% If send fails here the state machine will catch the tcp_closed
    %% and transition creating -> failed; no further reply needed.
    _ = erlkoenig_ct_rt:send_to_rt(Cmd, Data),
    ok.

creating_handle_rt_data(Reply, false = _Handshake, Data) ->
    %% First message: protocol handshake reply
    case erlkoenig_proto:check_handshake_reply(Reply) of
        ok ->
            case erlkoenig_ct_security:maybe_verify_signature(Data) of
                {ok, Data2} ->
                    creating_send_spawn(Data2),
                    {keep_state, Data2#ct_data{handshake = true}};
                {error, SigReason} ->
                    {next_state, failed,
                     Data#ct_data{error_reason = ct_error(signature_rejected,
                                                          "container signature rejected",
                                                          #{reason => SigReason})}}
            end;
        {error, Reason} ->
            {next_state, failed,
             Data#ct_data{error_reason = ct_error(handshake_failed,
                                                  "runtime handshake reply rejected during create",
                                                  #{reason => Reason, reply => Reply})}}
    end;
creating_handle_rt_data(Reply, true = _Handshake, Data) ->
    %% Second message: SPAWN reply
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_container_pid, #{child_pid := Pid, netns_path := Ns}} ->
            {next_state, namespace_ready,
             Data#ct_data{os_pid = Pid, netns_path = Ns}};
        {ok, reply_error, #{code := Code, message := ErrMsg}} ->
            Err = ?EK_ERROR(runtime, spawn_failed,
                            "erlkoenig_rt rejected CMD_SPAWN",
                            #{code => Code, message => ErrMsg,
                              binary => Data#ct_data.binary_path}),
            erlkoenig_error:emit(Err, Data#ct_data.id),
            {next_state, failed,
             Data#ct_data{error_reason = Err}};
        Other ->
            Err = ?EK_ERROR(runtime, unexpected_spawn_reply,
                            "unknown reply to CMD_SPAWN",
                            #{reply => Other}),
            erlkoenig_error:emit(Err, Data#ct_data.id),
            {next_state, failed,
             Data#ct_data{error_reason = Err}}
    end.

%% =================================================================
%% namespace_ready - Namespace exists, network setup window
%% =================================================================

namespace_ready(enter, _OldState, _Data) ->
    %% Cgroup + network setup, then GO.
    %% Done asynchronously via self() ! message to avoid enter callback
    %% restrictions (no next_state from enter).
    self() ! do_container_setup,
    keep_state_and_data;

namespace_ready(info, do_container_setup, Data) ->
    erlkoenig_ct_cgroup:do_container_setup(Data);

namespace_ready(info, {tcp, Sock, Reply}, #ct_data{sock = Sock} = Data) ->
    namespace_ready_handle_data(Reply, Data);

namespace_ready({call, From}, go, _Data) ->
    %% GO is now automatic after net setup. Just ack.
    {keep_state_and_data, [{reply, From, ok}]};

namespace_ready({call, _From}, stop_container, _Data) ->
    {keep_state_and_data, [postpone]};

namespace_ready({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, erlkoenig_ct_info:build_info(namespace_ready, Data)}]};

namespace_ready(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    {next_state, failed,
     Data#ct_data{sock = undefined,
                  error_reason = ct_error(socket_closed,
                                          "runtime socket closed during namespace setup",
                                          #{phase => namespace_ready})}};

namespace_ready(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock} = Data) ->
    {next_state, failed,
     Data#ct_data{sock = undefined,
                  error_reason = ct_error(socket_error,
                                          "runtime socket errored during namespace setup",
                                          #{phase => namespace_ready, reason => Reason})}};

namespace_ready(info, {poll_stats, _, _}, _Data) -> keep_state_and_data;
namespace_ready(info, check_restart, _Data) -> keep_state_and_data.

namespace_ready_handle_data(Reply, Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_runtime_event, Event} ->
            {keep_state, append_runtime_event(Event, Data)};
        {ok, reply_exited, ExitInfo} ->
            {next_state, stopped, Data#ct_data{exit_info = ExitInfo}};
        _Other ->
            keep_state_and_data
    end.

%% =================================================================
%% starting - GO sent, waiting for reply_ok
%% =================================================================

starting(enter, _OldState, _Data) ->
    {keep_state_and_data, [{state_timeout, ?GO_TIMEOUT, go_timeout}]};

starting(info, {tcp, Sock, Reply}, #ct_data{sock = Sock} = Data) ->
    starting_handle_data(Reply, Data);

starting(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    Err = ct_error(socket_closed,
                   "runtime socket closed while waiting for GO reply",
                   #{phase => starting}),
    Data2 = maybe_reply_go_error(Data, Err),
    {next_state, failed,
     Data2#ct_data{sock = undefined, error_reason = Err}};

starting(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock} = Data) ->
    Err = ct_error(socket_error,
                   "runtime socket errored while waiting for GO reply",
                   #{phase => starting, reason => Reason}),
    Data2 = maybe_reply_go_error(Data, Err),
    {next_state, failed,
     Data2#ct_data{sock = undefined, error_reason = Err}};

starting(state_timeout, go_timeout, Data) ->
    Err = ct_error(go_timeout,
                   "container GO timed out",
                   #{timeout_ms => ?GO_TIMEOUT}),
    Data2 = maybe_reply_go_error(Data, Err),
    {next_state, failed, Data2#ct_data{error_reason = Err}};

starting({call, From}, get_info, Data) ->
    {keep_state_and_data,
     [{reply, From, erlkoenig_ct_info:build_info(starting, Data)}]};

starting({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]};

%% Stale timer messages from the previous gen_statem incarnation may
%% arrive while we're bringing a fresh container up. Discard.
starting(info, {poll_stats, _, _}, _Data) -> keep_state_and_data;
starting(info, check_restart, _Data) -> keep_state_and_data.

%% =================================================================
%% running - Container executing
%% =================================================================

%% First entry into running for this gen_statem lifetime.
%%   - Normal spawn: entered from `starting` with first_running_entry_done=false
%%   - Init-recover after daemon crash: entered from `recovering` with the same
%%     false flag (init({recover, _}) uses the record default)
%% Both paths need the full registrations (pg, events, dns/dets/audit, token).
running(enter, _OldState, #ct_data{first_running_entry_done = false} = Data) ->
    running_first_entry(Data);
%% Same-session reconnect (`running → disconnected → recovering → running'):
%% the one-shot registrations already fired; firing them again would
%%   - pg:join a second time (pg is NOT idempotent — broadcasts
%%     would be delivered twice to self())
%%   - emit a duplicate `container_started' event, skewing ek output,
%%     metrics counters, and the event log
%%   - write a duplicate `volume_mounted' audit entry, making the
%%     mounted/released reconcile on audit trails go negative
%% Only the transient process/timer pair needs to be refreshed — stats
%% timers and the log publisher were orphaned by the disconnect window
%% and must be cancelled + restarted with fresh refs.
running(enter, _OldState, Data) ->
    erlkoenig_ct_observe:cancel_stats_timers(Data#ct_data.stats_timers),
    erlkoenig_ct_observe:maybe_stop_log_publisher(Data#ct_data.log_publisher),
    Timers = erlkoenig_ct_observe:start_stats_timers(Data#ct_data.publish),
    LogPub = erlkoenig_ct_observe:maybe_start_log_publisher(Data),
    {keep_state, Data#ct_data{stats_timers = Timers,
                              log_publisher = LogPub}};

running(info, {tcp, Sock, Reply}, #ct_data{sock = Sock} = Data) ->
    running_handle_data(Reply, Data);

running(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    %% Socket lost but container may still be alive (C runtime survives)
    logger:warning("container ~s: socket closed, entering disconnected state",
                   [Data#ct_data.id]),
    {next_state, disconnected, Data#ct_data{sock = undefined}};

running(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock} = Data) ->
    logger:error("container ~s: socket error ~p, entering disconnected state",
                 [Data#ct_data.id, Reason]),
    {next_state, disconnected, Data#ct_data{sock = undefined}};

running({call, From}, stop_container, Data) ->
    case erlkoenig_ct_rt:send_to_rt(erlkoenig_proto:encode_cmd_kill(15), Data) of
        ok ->
            {next_state, stopping,
             Data#ct_data{from = From, user_stopped = true}};
        {error, #{code := 'EK_RUNTIME_NOT_CONNECTED'}} = Err ->
            %% Socket was torn down under us — fail loud instead of
            %% transitioning to stopping and hanging the caller on a
            %% stop-timeout reply that will never fire.
            {keep_state_and_data, [{reply, From, Err}]};
        {error, _} = Err ->
            logger:warning("container ~s: stop command failed before stopping: ~p",
                           [Data#ct_data.id, Err]),
            {keep_state_and_data, [{reply, From, Err}]}
    end;

running({call, From}, {kill, Signal}, Data) ->
    case erlkoenig_ct_rt:send_to_rt(erlkoenig_proto:encode_cmd_kill(Signal), Data) of
        ok ->
            {next_state, stopping, Data, [{reply, From, ok}]};
        {error, #{code := 'EK_RUNTIME_NOT_CONNECTED'}} = Err ->
            {keep_state_and_data, [{reply, From, Err}]};
        {error, _} = Err ->
            logger:warning("container ~s: kill command failed before stopping: ~p",
                           [Data#ct_data.id, Err]),
            {keep_state_and_data, [{reply, From, Err}]}
    end;

running({call, From}, {attach, OutputPid}, Data) ->
    {keep_state, Data#ct_data{output = OutputPid}, [{reply, From, ok}]};

running({call, From}, {resize, Rows, Cols}, #ct_data{pty = true} = Data) ->
    Reply = erlkoenig_ct_rt:send_to_rt(
              erlkoenig_proto:encode_cmd_resize(Rows, Cols), Data),
    {keep_state_and_data, [{reply, From, Reply}]};

running({call, From}, {resize, _Rows, _Cols}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_pty}}]};

running({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, erlkoenig_ct_info:build_info(running, Data)}]};

running(info, {poll_stats, Interval, Metrics}, Data) ->
    Data2 = erlkoenig_ct_observe:poll_and_publish_stats(Metrics, Data),
    _Ref = erlang:send_after(Interval, self(), {poll_stats, Interval, Metrics}),
    {keep_state, Data2};

running(cast, {send_input, InputData}, Data) ->
    %% Cast: no reply path. send_to_rt already logs a warning on
    %% runtime failure — there's nobody to hand the error to.
    _ = erlkoenig_ct_rt:send_to_rt(
          erlkoenig_proto:encode_cmd_stdin(InputData), Data),
    keep_state_and_data.

%% Shared first-entry init. Fires on normal spawn (`starting → running`)
%% and on init-recover (daemon restart reconnecting to an already-running
%% C runtime); both paths need the fresh ecosystem to learn about the
%% container. `first_running_entry_done` is set so same-session
%% reconnects take the refresh-only clause.
running_first_entry(Data) ->
    %% Confirm the Phase-B reservation before joining the running-set used by
    %% node_resources snapshots. confirm_running/1 publishes a snapshot; if
    %% this process is already in erlkoenig_cts, the snapshot calls back into
    %% us with get_info while we are still waiting on confirm_running -> timeout.
    erlkoenig_ct_security:confirm_resource_admission(Data),
    pg:join(erlkoenig_pg, erlkoenig_cts, self()),
    erlkoenig_events:notify({container_started, Data#ct_data.id,
                             Data#ct_data.name, self()}),
    erlkoenig_ct_resources:dns_register(Data),
    erlkoenig_ct_resources:dns_filter_register(Data),
    erlkoenig_ct_resources:dets_register(Data),
    erlkoenig_ct_resources:audit_volumes_mounted(Data),
    %% The spawn is complete — release the admission token so another
    %% waiter can proceed. The container is now using its long-lived
    %% resources (cgroup, netns, firewall) which don't count against
    %% the bounded-concurrency spawn gate.
    erlkoenig_ct_security:release_admission_token(Data),
    Timers = erlkoenig_ct_observe:start_stats_timers(Data#ct_data.publish),
    LogPub = erlkoenig_ct_observe:maybe_start_log_publisher(Data),
    {keep_state, Data#ct_data{started_at = erlang:monotonic_time(millisecond),
                              stats_timers = Timers,
                              log_publisher = LogPub,
                              admission_token = undefined,
                              first_running_entry_done = true}}.

%% =================================================================
%% stopping - SIGTERM sent, waiting for exit
%% =================================================================

stopping(enter, _OldState, Data) ->
    erlkoenig_ct_observe:cancel_stats_timers(Data#ct_data.stats_timers),
    {keep_state, Data#ct_data{stats_timers = []},
     [{state_timeout, ?STOP_TIMEOUT, force_kill}]};

stopping(info, {poll_stats, _, _}, _Data) ->
    keep_state_and_data;

stopping(info, {tcp, Sock, Reply}, #ct_data{sock = Sock} = Data) ->
    stopping_handle_data(Reply, Data);

stopping(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    {next_state, stopped, Data#ct_data{sock = undefined}};

stopping(info, {tcp_error, Sock, _Reason}, #ct_data{sock = Sock} = Data) ->
    {next_state, stopped, Data#ct_data{sock = undefined}};

stopping({call, From}, get_info, Data) ->
    {keep_state_and_data,
     [{reply, From, erlkoenig_ct_info:build_info(stopping, Data)}]};

stopping(state_timeout, force_kill, Data) when Data#ct_data.sock =/= undefined ->
    %% Best effort — if the socket went away between the guard and
    %% the send, the give_up timeout below will trip.
    _ = erlkoenig_ct_rt:send_to_rt(erlkoenig_proto:encode_cmd_kill(9), Data),
    {keep_state_and_data, [{state_timeout, ?STOP_TIMEOUT, give_up}]};

stopping(state_timeout, give_up, Data) ->
    Err = ct_error(kill_timeout,
                   "container did not exit after forced kill",
                   #{timeout_ms => ?STOP_TIMEOUT}),
    Data2 = maybe_reply_stop(Data, {error, Err}),
    {next_state, failed, Data2#ct_data{error_reason = Err}};

stopping({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]}.

%% -- Data dispatch helpers (shared between port and socket modes) --

starting_handle_data(Reply, Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_ok, _} ->
            Data2 = maybe_reply_go(Data),
            {next_state, running, Data2};
        {ok, reply_runtime_event, Event} ->
            {keep_state, append_runtime_event(Event, Data)};
        {ok, reply_exited, ExitInfo} ->
            %% Child exited before we got reply_ok
            Data2 = maybe_reply_go(Data),
            {next_state, stopped,
             Data2#ct_data{exit_info = ExitInfo}};
        {ok, reply_error, #{code := Code, message := ErrMsg}} ->
            Err = ct_error(go_failed,
                           "erlkoenig_rt rejected CMD_GO",
                           #{code => Code, message => ErrMsg}),
            Data2 = maybe_reply_go_error(Data, Err),
            {next_state, failed,
             Data2#ct_data{error_reason = Err}};
        {ok, reply_stdout, #{data := Chunk}} ->
            erlkoenig_ct_observe:forward_output(stdout, Chunk, Data),
            keep_state_and_data;
        {ok, reply_stderr, #{data := Chunk}} ->
            erlkoenig_ct_observe:forward_output(stderr, Chunk, Data),
            keep_state_and_data;
        Other ->
            Err = ct_error(unexpected_reply,
                           "unexpected runtime reply while starting container",
                           #{phase => starting, reply => Other}),
            {next_state, failed,
             Data#ct_data{error_reason = Err}}
    end.

running_handle_data(Reply, Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_runtime_event, Event} ->
            {keep_state, append_runtime_event(Event, Data)};
        {ok, reply_exited, ExitInfo} ->
            {next_state, stopped, Data#ct_data{exit_info = ExitInfo}};
        {ok, reply_stdout, #{data := Chunk}} ->
            erlkoenig_ct_observe:forward_output(stdout, Chunk, Data),
            keep_state_and_data;
        {ok, reply_stderr, #{data := Chunk}} ->
            erlkoenig_ct_observe:forward_output(stderr, Chunk, Data),
            keep_state_and_data;
        {ok, reply_metrics_event, Event} ->
            erlkoenig_events:notify({container_metrics,
                                     Data#ct_data.id,
                                     Data#ct_data.name, Event}),
            keep_state_and_data;
        _Other ->
            keep_state_and_data
    end.

stopping_handle_data(Reply, Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_runtime_event, Event} ->
            {keep_state, append_runtime_event(Event, Data)};
        {ok, reply_exited, ExitInfo} ->
            {next_state, stopped, Data#ct_data{exit_info = ExitInfo}};
        {ok, reply_stdout, #{data := Chunk}} ->
            erlkoenig_ct_observe:forward_output(stdout, Chunk, Data),
            keep_state_and_data;
        {ok, reply_stderr, #{data := Chunk}} ->
            erlkoenig_ct_observe:forward_output(stderr, Chunk, Data),
            keep_state_and_data;
        _Other ->
            keep_state_and_data
    end.

append_runtime_event(Event, Data) ->
    Step0 = Event#{
        source => runtime,
        observed_at_ms => erlang:system_time(millisecond)
    },
    Step = maps:filter(fun(_Key, Value) -> Value =/= <<>> end, Step0),
    Data#ct_data{runtime_timeline = Data#ct_data.runtime_timeline ++ [Step]}.

%% =================================================================
%% stopped - Container exited, check restart policy
%% =================================================================

stopped(enter, _OldState, Data) ->
    pg:leave(erlkoenig_pg, erlkoenig_cts, self()),
    erlkoenig_ct_observe:cancel_stats_timers(Data#ct_data.stats_timers),
    erlkoenig_ct_observe:maybe_stop_log_publisher(Data#ct_data.log_publisher),
    erlkoenig_ct_net:firewall_remove(Data#ct_data.id),
    erlkoenig_ct_volume:cleanup_fuse(Data),

    erlkoenig_ct_rt:terminate_os_pid(Data#ct_data.rt_pid),
    erlkoenig_ct_resources:safe_sock_close(Data#ct_data.sock),
    erlkoenig_ct_resources:cleanup_socket_file(Data#ct_data.socket_path),
    erlkoenig_ct_resources:dns_unregister(Data),
    erlkoenig_ct_resources:dns_filter_unregister(Data),
    erlkoenig_ct_resources:dets_unregister(Data),
    erlkoenig_ct_resources:audit_volumes_released(Data),
    erlkoenig_ct_resources:cleanup_ephemeral_volumes(Data),
    %% Release the admission token if we're stopping before `running`
    %% fired (early failure path). No-op if the token was already
    %% returned.
    erlkoenig_ct_security:release_admission_token(Data),
    erlkoenig_ct_security:release_resource_admission(Data),
    erlkoenig_ct_observe:notify_stopped(Data),
    Data2 = maybe_reply_stop(
              Data#ct_data{sock = undefined, fuse_mount = undefined,
                           stats_timers = [], log_publisher = undefined},
              ok),
    case Data2#ct_data.pod_supervised of
        true ->
            %% Pod supervisor handles restart — propagate exit reason.
            %% Full cleanup: IPVLAN slave, cgroup, IP — so fresh resources
            %% are allocated on supervisor restart.
            case pod_supervised_cleanup(Data2, stopped) of
                {ok, Data3} ->
                    %% Pod-supervised cycle never enters `restarting` (the
                    %% gen_statem stops here and the OTP supervisor respawns
                    %% it from scratch), so the quarantine circuit breaker
                    %% would never see a crashloop without this hook. Record
                    %% the crash now, but only for actual failure exits and
                    %% only when the cause is NOT quarantine itself.
                    case should_record_terminal_crash(Data3, false) of
                        true ->
                            _ = erlkoenig_ct_security:safe_record_crash(
                                  Data3#ct_data.binary_path);
                        false ->
                            ok
                    end,
                    ExitReason = erlkoenig_ct_opts:pod_exit_reason(Data3),
                    {stop, ExitReason, Data3};
                {error, CleanupReason, Data3} ->
                    {stop, {shutdown, {container_cleanup_failed, CleanupReason}}, Data3}
            end;
        false ->
            self() ! check_restart,
            {keep_state, Data2}
    end;

stopped(info, check_restart, Data) ->
    %% handle_check_restart returns either `{next_state, restarting, _}'
    %% (will restart) or `{keep_state, Data2}' (terminal).  The
    %% terminal path used to `{stop, normal, Data2}' the gen_statem to
    %% avoid a lingering "zombie" in `supervisor:which_children/1'.
    %% That broke post-mortem inspection: integration tests 01
    %% (Natural exit), 08 (File injection), 20 (BEAM survives OOM)
    %% spawn a container, wait for it to exit, then call
    %% `erlkoenig:inspect/1' to verify final state — which requires
    %% the gen_statem to still be alive in `stopped'.
    %% Keep the state machine running; callers that want hard
    %% teardown can `erlkoenig:stop/1' explicitly, which transitions
    %% through the same cleanup path again as a no-op.
    handle_check_restart(Data);
%% Stats poll / TCP events may already be in the mailbox when we enter
%% this state — cancel_timer/1 removes the scheduled send but cannot
%% pull back messages that already made it through. Ignore them.
stopped(info, {poll_stats, _, _}, _Data) ->
    keep_state_and_data;
stopped(info, {tcp_closed, _}, _Data) ->
    keep_state_and_data;
stopped(info, {tcp_error, _, _}, _Data) ->
    keep_state_and_data;
stopped(info, {tcp, _, _}, _Data) ->
    keep_state_and_data;

stopped({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, erlkoenig_ct_info:build_info(stopped, Data)}]};

stopped({call, From}, stop_container, Data) ->
    {keep_state, Data#ct_data{user_stopped = true}, [{reply, From, ok}]};

stopped({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, stopped}}]}.

%% =================================================================
%% restarting - Backoff wait before re-creating the container
%% =================================================================

restarting(enter, _OldState, Data) ->
    Backoff = erlkoenig_ct_opts:backoff_ms(Data#ct_data.restart_count),
    %% A non-user restart means the previous incarnation exited
    %% unexpectedly. Feed the binary's hash to the quarantine circuit
    %% breaker so a tight crashloop trips the threshold even when the
    %% gen_statem path is stopped → restarting (no `failed` state
    %% entered). Quarantine-triggered failures don't count themselves.
    case error_code(Data#ct_data.error_reason) of
        'EK_RUNTIME_BINARY_QUARANTINED' -> ok;
        _ -> _ = erlkoenig_ct_security:safe_record_crash(Data#ct_data.binary_path)
    end,
    erlkoenig_events:notify({container_restarting, Data#ct_data.id,
                             Data#ct_data.name,
                             Data#ct_data.restart_count}),
    logger:info("container ~s restarting in ~pms (attempt ~p)",
                [Data#ct_data.id, Backoff, Data#ct_data.restart_count]),
    {keep_state_and_data, [{state_timeout, Backoff, do_restart}]};

restarting(state_timeout, do_restart, Data) ->
    %% Reset transient state, keep identity + config + restart count.
    %% first_running_entry_done MUST reset to false so the new incarnation
    %% of the container fires its one-shot registrations (pg, events,
    %% dns, audit) at running(enter). Leaving it true would make
    %% subscribers miss the restart — no container_started event, no
    %% audit `volume_mounted', no pg membership for broadcasts.
    {next_state, creating, Data#ct_data{
        os_pid       = undefined,
        rt_pid       = undefined,
        netns_path   = undefined,
        net_info     = undefined,
        exit_info    = undefined,
        error_reason = undefined,
        from         = undefined,
        user_stopped = false,
        handshake    = false,
        sock         = undefined,
        socket_path  = undefined,
        fuse_mount   = undefined,
        tmpfs_mounts = [],
        first_running_entry_done = false
    }};

restarting({call, From}, stop_container, Data) ->
    %% User stops during backoff: release IP, go to final stopped.
    Data2 = erlkoenig_ct_resources:release_ip(Data),
    {next_state, stopped,
     Data2#ct_data{user_stopped = true, net_info = undefined},
     [{reply, From, ok}]};

restarting({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, erlkoenig_ct_info:build_info(restarting, Data)}]};

restarting({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, restarting}}]};

%% Stale messages from previous instance may still be in mailbox during
%% the restart backoff — discard.
restarting(info, {poll_stats, _, _}, _Data) ->
    keep_state_and_data;
restarting(info, {tcp_closed, _}, _Data) ->
    keep_state_and_data;
restarting(info, {tcp_error, _, _}, _Data) ->
    keep_state_and_data;
restarting(info, {tcp, _, _}, _Data) ->
    keep_state_and_data;
restarting(info, check_restart, _Data) ->
    keep_state_and_data.

%% =================================================================
%% failed - Error state, process stays alive for inspection
%% =================================================================

failed(enter, _OldState, Data) ->
    pg:leave(erlkoenig_pg, erlkoenig_cts, self()),
    erlkoenig_ct_observe:cancel_stats_timers(Data#ct_data.stats_timers),
    %% Stop the log publisher if it was started — `stopping → failed`
    %% (e.g. kill_timeout) reaches this state AFTER `running(enter, _)`
    %% has already spawned a publisher. Without this call the publisher
    %% stays alive as a process with a dead container attached to it,
    %% leaking one process per crash-under-kill on long-lived nodes.
    %% Mirrors `stopped(enter, _)`.
    erlkoenig_ct_observe:maybe_stop_log_publisher(Data#ct_data.log_publisher),
    erlkoenig_ct_net:firewall_remove(Data#ct_data.id),
    erlkoenig_ct_volume:cleanup_fuse(Data),

    erlkoenig_ct_rt:terminate_os_pid(Data#ct_data.rt_pid),
    erlkoenig_ct_resources:safe_sock_close(Data#ct_data.sock),
    erlkoenig_ct_resources:cleanup_socket_file(Data#ct_data.socket_path),
    erlkoenig_ct_resources:dns_unregister(Data),
    erlkoenig_ct_resources:dns_filter_unregister(Data),
    erlkoenig_ct_resources:dets_unregister(Data),
    %% Audit volume release here too — a failed container still held
    %% volumes while alive, so the audit trail needs the release event
    %% to balance the earlier volume_mounted entries. Previously only
    %% `stopped` emitted these, so crash-path containers left unbalanced
    %% audit records.
    erlkoenig_ct_resources:audit_volumes_released(Data),
    erlkoenig_ct_resources:cleanup_ephemeral_volumes(Data),
    erlkoenig_ct_security:release_admission_token(Data),
    erlkoenig_ct_security:release_resource_admission(Data),
    %% Record the crash against the binary's hash so the quarantine
    %% circuit breaker can spot crashloops. Quarantine failures caused
    %% by quarantine itself don't feed back into the counter — otherwise
    %% a quarantined binary would keep driving its own quarantine deeper.
    case error_code(Data#ct_data.error_reason) of
        'EK_RUNTIME_BINARY_QUARANTINED' -> ok;
        _ -> _ = erlkoenig_ct_security:safe_record_crash(Data#ct_data.binary_path)
    end,
    erlkoenig_events:notify({container_failed, Data#ct_data.id,
                             Data#ct_data.name,
                             Data#ct_data.error_reason}),
    logger:error("container ~s failed: ~p",
                 [Data#ct_data.id, Data#ct_data.error_reason]),
    Data2 = Data#ct_data{sock = undefined, fuse_mount = undefined,
                         stats_timers = [], log_publisher = undefined},
    case Data2#ct_data.pod_supervised of
        true ->
            case pod_supervised_cleanup(Data2, failed) of
                {ok, Data3} ->
                    Reason = case Data3#ct_data.error_reason of
                        undefined -> {container_failed, unknown, 0};
                        R -> {container_failed, R, 0}
                    end,
                    {stop, Reason, Data3};
                {error, CleanupReason, Data3} ->
                    {stop, {shutdown, {container_cleanup_failed, CleanupReason}}, Data3}
            end;
        false ->
            self() ! check_restart,
            {keep_state, Data2}
    end;

failed(info, {poll_stats, _, _}, _Data) ->
    keep_state_and_data;

failed(info, check_restart, Data) ->
    handle_check_restart(Data);

failed({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, erlkoenig_ct_info:build_info(failed, Data)}]};

failed({call, From}, stop_container, Data) ->
    {keep_state, Data#ct_data{user_stopped = true}, [{reply, From, ok}]};

failed({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, failed}}]}.

%% =================================================================
%% recovering - Reconnecting to still-running container after crash
%% =================================================================

%% Entry from `disconnected' — that state already opened a socket,
%% sent query_status and flipped it active, so the reply is in flight.
%% Opening a second socket here would leak the first one (its messages
%% would arrive with the old Sock and fail pattern-match against the
%% new one stored in #ct_data, then be dropped by gen_statem's default
%% info handler). Just wait for the reply.
recovering(enter, disconnected, _Data) ->
    keep_state_and_data;
%% Entry from init({recover, _}) — fresh gen_statem after daemon crash
%% reconnecting to an already-running C runtime. No sock yet.
recovering(enter, _OldState, Data) ->
    case erlkoenig_ct_rt:connect_to_runtime(Data) of
        {ok, Sock} ->
            NewData = Data#ct_data{sock = Sock},
            ok = gen_tcp:send(Sock, erlkoenig_proto:encode_cmd_query_status()),
            {keep_state, NewData};
        {error, _} ->
            %% Can't connect — C runtime is probably dead; the
            %% 5000ms recovery_timeout set at init will transition
            %% us to `failed'.
            keep_state_and_data
    end;

recovering(info, {tcp, Sock, Reply}, #ct_data{sock = Sock} = Data) ->
    %% Got response from C runtime
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_status, #{state := State, child_pid := ChildPid}} when
                State > 0, ChildPid > 0 ->
            %% Container is still running! Transition to running.
            %% Note: pg:join was done at the first running(enter, starting, _)
            %% and self() is still in erlkoenig_cts (we never went through
            %% stopped, which is the only state that leaves). Joining again
            %% would double-subscribe us to broadcasts.
            logger:info("container ~s recovered successfully (pid ~p)",
                        [Data#ct_data.id, ChildPid]),
            ok = inet:setopts(Sock, [{active, true}]),
            {next_state, running, Data#ct_data{
                os_pid = ChildPid,
                started_at = erlang:monotonic_time(millisecond)
            }};
        {ok, reply_status, _} ->
            %% Container died while we were gone
            logger:info("container ~s died during disconnect",
                        [Data#ct_data.id]),
            {next_state, stopped, Data};
        {ok, reply_exited, ExitInfo} ->
            logger:info("container ~s exited during disconnect",
                        [Data#ct_data.id]),
            {next_state, stopped, Data#ct_data{exit_info = ExitInfo}};
        _Other ->
            keep_state_and_data
    end;

recovering(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    logger:warning("container ~s: socket closed during recovery",
                   [Data#ct_data.id]),
    {next_state, failed,
     Data#ct_data{sock = undefined,
                  error_reason = ct_error(recovery_socket_closed,
                                          "runtime socket closed during recovery",
                                          #{phase => recovering})}};

recovering(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock} = Data) ->
    logger:error("container ~s: socket error during recovery: ~p",
                 [Data#ct_data.id, Reason]),
    {next_state, failed,
     Data#ct_data{sock = undefined,
                  error_reason = ct_error(recovery_socket_error,
                                          "runtime socket errored during recovery",
                                          #{phase => recovering, reason => Reason})}};

recovering(state_timeout, recovery_timeout, Data) ->
    %% Couldn't recover in time
    logger:warning("container ~s: recovery timeout", [Data#ct_data.id]),
    {next_state, failed,
     Data#ct_data{error_reason = ct_error(recovery_timeout,
                                          "container recovery timed out",
                                          #{timeout_ms => 5000})}};

recovering({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, erlkoenig_ct_info:build_info(recovering, Data)}]};

recovering({call, From}, stop_container, Data) ->
    %% Kill via OS if possible
    erlkoenig_ct_rt:kill_os_pid(Data#ct_data.os_pid),
    {next_state, stopped,
     Data#ct_data{user_stopped = true}, [{reply, From, ok}]};

recovering({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]};

recovering(info, {poll_stats, _, _}, _Data) -> keep_state_and_data;
recovering(info, check_restart, _Data) -> keep_state_and_data.

%% =================================================================
%% disconnected - Socket lost while running, attempting reconnect
%% =================================================================

disconnected(enter, _OldState, Data) ->
    %% Start reconnect timer. Reset attempt counter so a subsequent
    %% disconnect (e.g. after a successful recovery + new socket drop)
    %% gets a fresh retry budget.
    logger:info("container ~s: disconnected, will attempt reconnect",
                [Data#ct_data.id]),
    {keep_state, Data#ct_data{reconnect_attempts = 0},
     [{state_timeout, 1000, try_reconnect}]};

disconnected(state_timeout, try_reconnect, Data) ->
    case erlkoenig_ct_rt:connect_to_runtime(Data) of
        {ok, Sock} ->
            %% connect_to_runtime now does the sync handshake AND leaves
            %% the socket in {active, true}, so query_status can go out
            %% directly and the reply arrives as an info message.
            NewData = Data#ct_data{sock = Sock, reconnect_attempts = 0},
            ok = gen_tcp:send(Sock, erlkoenig_proto:encode_cmd_query_status()),
            {next_state, recovering, NewData,
             [{state_timeout, 5000, recovery_timeout}]};
        {error, _} ->
            %% Bounded retry — 30 × 1s = 30s. The original comment
            %% claimed this budget existed; no counter did. A dead
            %% runtime now produces a clean transition to `failed'
            %% instead of a zombie gen_statem retrying forever.
            NewAttempts = Data#ct_data.reconnect_attempts + 1,
            case NewAttempts >= ?RECONNECT_MAX_ATTEMPTS of
                true ->
                    logger:warning("container ~s: reconnect exhausted "
                                   "after ~p attempts",
                                   [Data#ct_data.id, NewAttempts]),
                    {next_state, failed,
                     Data#ct_data{reconnect_attempts = NewAttempts,
                                  error_reason = ct_error(reconnect_exhausted,
                                                          "runtime reconnect attempts exhausted",
                                                          #{attempts => NewAttempts})}};
                false ->
                    {keep_state,
                     Data#ct_data{reconnect_attempts = NewAttempts},
                     [{state_timeout, 1000, try_reconnect}]}
            end
    end;


disconnected({call, From}, stop_container, Data) ->
    %% Can't send SIGTERM via socket, use kill directly
    erlkoenig_ct_rt:kill_os_pid(Data#ct_data.os_pid),
    {next_state, stopped,
     Data#ct_data{user_stopped = true}, [{reply, From, ok}]};

disconnected({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, erlkoenig_ct_info:build_info(disconnected, Data)}]};

disconnected({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, disconnected}}]};

disconnected(info, {poll_stats, _, _}, _Data) -> keep_state_and_data;
disconnected(info, check_restart, _Data) -> keep_state_and_data.

%% =================================================================
%% Internal
%% =================================================================

%% Stats-polling timers, per-metric publishers, log-publisher
%% start/stop, stdout/stderr forwarding, and `notify_stopped/1'
%% live in erlkoenig_ct_observe. `build_info/2' stayed here because
%% every `get_info' state-callback calls it directly — pulling it
%% out would buy less than it costs.

%% -- Restart logic ------------------------------------------------

%% `do_container_setup/1' lives in erlkoenig_ct_cgroup — it is the
%% cgroup-first orchestrator called from `namespace_ready(enter, _)'.

%% `do_container_net_setup/1' lives in erlkoenig_ct_net.

%% -- Restart logic ------------------------------------------------

-spec handle_check_restart(#ct_data{}) ->
    {next_state, atom(), #ct_data{}} | {keep_state, #ct_data{}}.
handle_check_restart(Data) ->
    case restart_cleanup(Data) of
        {ok, Data2} ->
            case erlkoenig_ct_opts:should_restart(Data2) of
                true ->
                    NewCount = Data2#ct_data.restart_count + 1,
                    persist_restart_count(Data2#ct_data.name, NewCount),
                    {next_state, restarting,
                     Data2#ct_data{restart_count = NewCount}};
                false ->
                    case should_record_terminal_crash(Data2, false) of
                        true ->
                            _ = erlkoenig_ct_security:safe_record_crash(
                                  Data2#ct_data.binary_path);
                        false ->
                            ok
                    end,
                    Data3 = erlkoenig_ct_resources:release_ip(Data2),
                    {keep_state, Data3}
            end;
        {error, CleanupReason, Data2} ->
            Err = ct_error(cleanup_failed,
                           "container cleanup before restart failed",
                           #{reason => CleanupReason}),
            erlkoenig_error:emit(Err, Data2#ct_data.id),
            logger:error("container ~s cleanup before restart failed: ~p",
                         [Data2#ct_data.id, CleanupReason]),
            {keep_state, Data2#ct_data{error_reason = Err}}
    end.

restart_cleanup(Data) ->
    restart_cleanup_result(
      Data,
      erlkoenig_ct_net:teardown_link(Data),
      erlkoenig_ct_cgroup:destroy_cgroup(Data)).

restart_cleanup_result(Data, ok, ok) ->
    {ok, Data#ct_data{net_info = undefined}};
restart_cleanup_result(Data, {error, Reason}, _CgroupResult) ->
    {error, {network_teardown_failed, Reason}, Data};
restart_cleanup_result(Data, NetResult, _CgroupResult) when NetResult =/= ok ->
    {error, {network_teardown_failed, NetResult}, Data};
restart_cleanup_result(Data, ok, {error, Reason}) ->
    {error, {cgroup_destroy_failed, Reason}, Data};
restart_cleanup_result(Data, ok, CgroupResult) ->
    {error, {cgroup_destroy_failed, CgroupResult}, Data}.

pod_supervised_cleanup(Data, State) ->
    case restart_cleanup(Data) of
        {ok, Data2} ->
            {ok, erlkoenig_ct_resources:release_ip(Data2)};
        {error, CleanupReason, Data2} ->
            Err = ct_error(cleanup_failed,
                           "pod-supervised container cleanup failed",
                           #{state => State, reason => CleanupReason}),
            erlkoenig_error:emit(Err, Data2#ct_data.id),
            logger:error("pod-supervised container ~s cleanup failed in ~p: ~p",
                         [Data2#ct_data.id, State, CleanupReason]),
            {error, CleanupReason, Data2#ct_data{error_reason = Err}}
    end.

-spec should_record_terminal_crash(#ct_data{}, boolean()) -> boolean().
should_record_terminal_crash(_Data, true) ->
    %% Restarting paths record in `restarting(enter, ...)`; recording here too
    %% would count one crash twice and trip quarantine too early.
    false;
should_record_terminal_crash(Data, false) ->
    case erlkoenig_ct_opts:is_failure_exit(Data) of
        false ->
            false;
        true ->
            error_code(Data#ct_data.error_reason) =/= 'EK_RUNTIME_BINARY_QUARANTINED'
    end.

%% Restart policy (validate_restart/1, normalize_restart/1,
%% should_restart/1, is_failure_exit/1, pod_exit_reason/1,
%% backoff_ms/1) lives in erlkoenig_ct_opts — pure, side-effect
%% free, easier to unit-test.

%% `notify_stopped/1' lives in erlkoenig_ct_observe.

%% `write_container_files/2' lives in erlkoenig_ct_net (it's part of
%% the pre-GO sequence, right before `send_to_rt(CMD_GO)').

%% DNS register/unregister, DNS egress allowlist register/unregister,
%% DETS register/unregister, topology helpers (netns_path,
%% cgroup_path_for_id), and socket cleanup
%% (safe_sock_close, cleanup_socket_file) live in
%% erlkoenig_ct_resources — they are the counterpart of the setup
%% flow and are all called from `stopped(enter, _)' /
%% `failed(enter, _)' as a cleanup checklist.
%%
%% Socket I/O (send_to_rt/2, rt_io_handle/1, maybe_set_active/2,
%% socket_dir/0, make_socket_path/1, wait_and_connect/{2,3},
%% connect_to_runtime/1, kill_os_pid/1, sync_rt_command/3,
%% handle_setup_reply/3) lives in erlkoenig_ct_rt.

%% firewall_add/4, firewall_remove/1, maybe_apply_container_nft/1,
%% teardown_link/1, try_net_setup_with_retry/7, try_net_setup_loop/3,
%% zone_dns_ip/1, ip4_to_u32/1, and effective_dns_ip/1 live in
%% erlkoenig_ct_net — grouped as the create/teardown pair of the
%% container-side network + firewall lifecycle.
%%
%% `release_ip/1' lives in erlkoenig_ct_resources.

%% Seccomp profile name<->id, capability bit math, socket-mount
%% merger, and `to_bin/1` live in erlkoenig_ct_opts. Pure functions,
%% no gen_statem or ETS dependencies.

%% destroy_cgroup/1, setup_cgroup/3, setup_device_filter/2, and
%% setup_metrics/2 live in erlkoenig_ct_cgroup alongside
%% do_container_setup/1 — they form the cgroup subsystem's
%% create/destroy pair plus its two eBPF attachments.

-spec make_id() -> erlkoenig:container_id().
make_id() ->
    <<A:32, B:16, C:16, D:16, E:48>> = crypto:strong_rand_bytes(16),
    list_to_binary(io_lib:format(
      "~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b",
      [A, B, C band 16#0fff bor 16#4000,
       D band 16#3fff bor 16#8000, E])).

%% C-runtime executable discovery (rt_path/0, find_rt/0,
%% find_first/1, check_path/1, check_priv_dir/0, check_build_dir/0)
%% lives in erlkoenig_ct_rt_discover — different change frequency
%% from the socket-I/O helpers, isolated here.

%% `audit_volumes_mounted/1' and `audit_volumes_released/1' live in
%% erlkoenig_ct_resources.

%% Volume resolution, FUSE rootfs build/mount/cleanup live in
%% erlkoenig_ct_volume. `cleanup_ephemeral_volumes/1' lives in
%% erlkoenig_ct_resources.

%% Pre-spawn gates (admission_then_quarantine/2 + the safe_*
%% wrappers + admission_scope/1 + release_admission_token/1 +
%% safe_record_crash/1 + format_hash_prefix/1) live in
%% erlkoenig_ct_security — security-policy boundary of the
%% state machine.

%% `build_info/2' (+ its private helpers `maybe_add_optional_fields/3'
%% and `maybe_put/3') lives in erlkoenig_ct_info. The state callbacks
%% keep the `{reply, From, build_info(State, Data)}' shape; only the
%% projection of `#ct_data{}' into the public map moved.
%% `maybe_add_stats/3' lives in erlkoenig_ct_observe.

ct_error(socket_closed, Context, Data) ->
    ?EK_ERROR(ct, socket_closed, Context, Data);
ct_error(socket_error, Context, Data) ->
    ?EK_ERROR(ct, socket_error, Context, Data);
ct_error(spawn_timeout, Context, Data) ->
    ?EK_ERROR(ct, spawn_timeout, Context, Data);
ct_error(admission_timeout, Context, Data) ->
    ?EK_ERROR(ct, admission_timeout, Context, Data);
ct_error(admission_queue_full, Context, Data) ->
    ?EK_ERROR(ct, admission_queue_full, Context, Data);
ct_error(resource_admission_denied, Context, Data) ->
    ?EK_ERROR(ct, resource_admission_denied, Context, Data);
ct_error(admission_unavailable, Context, Data) ->
    ?EK_ERROR_S(critical, ct, admission_unavailable, Context, Data);
ct_error(quarantine_unavailable, Context, Data) ->
    ?EK_ERROR_S(critical, ct, quarantine_unavailable, Context, Data);
ct_error(cgroup_setup_failed, Context, Data) ->
    ?EK_ERROR_S(critical, ct, cgroup_setup_failed, Context, Data);
ct_error(cleanup_failed, Context, Data) ->
    ?EK_ERROR_S(critical, ct, cleanup_failed, Context, Data);
ct_error(signature_rejected, Context, Data) ->
    ?EK_ERROR(ct, signature_rejected, Context, Data);
ct_error(handshake_failed, Context, Data) ->
    ?EK_ERROR(ct, handshake_failed, Context, Data);
ct_error(go_timeout, Context, Data) ->
    ?EK_ERROR(ct, go_timeout, Context, Data);
ct_error(go_failed, Context, Data) ->
    ?EK_ERROR(ct, go_failed, Context, Data);
ct_error(unexpected_reply, Context, Data) ->
    ?EK_ERROR(ct, unexpected_reply, Context, Data);
ct_error(kill_timeout, Context, Data) ->
    ?EK_ERROR(ct, kill_timeout, Context, Data);
ct_error(recovery_socket_closed, Context, Data) ->
    ?EK_ERROR(ct, recovery_socket_closed, Context, Data);
ct_error(recovery_socket_error, Context, Data) ->
    ?EK_ERROR(ct, recovery_socket_error, Context, Data);
ct_error(recovery_timeout, Context, Data) ->
    ?EK_ERROR(ct, recovery_timeout, Context, Data);
ct_error(reconnect_exhausted, Context, Data) ->
    ?EK_ERROR(ct, reconnect_exhausted, Context, Data).

attach_container(#{type := _, reason := _} = Err, ContainerId) ->
    Err#{container => ContainerId};
attach_container(Err, _ContainerId) ->
    Err.

error_code(#{code := Code}) -> Code;
error_code(_) -> undefined.

-spec maybe_reply_go(#ct_data{}) -> #ct_data{}.
maybe_reply_go(#ct_data{from = undefined} = Data) ->
    Data;
maybe_reply_go(#ct_data{from = From} = Data) ->
    gen_statem:reply(From, ok),
    Data#ct_data{from = undefined}.

-spec maybe_reply_go_error(#ct_data{}, term()) -> #ct_data{}.
maybe_reply_go_error(#ct_data{from = undefined} = Data, _Reason) ->
    Data;
maybe_reply_go_error(#ct_data{from = From} = Data, Reason) ->
    gen_statem:reply(From, {error, Reason}),
    Data#ct_data{from = undefined}.

-spec maybe_reply_stop(#ct_data{}, term()) -> #ct_data{}.
maybe_reply_stop(#ct_data{from = undefined} = Data, _Reply) ->
    Data;
maybe_reply_stop(#ct_data{from = From} = Data, Reply) ->
    gen_statem:reply(From, Reply),
    Data#ct_data{from = undefined}.

%% FUSE rootfs build/mount/cleanup lives in erlkoenig_ct_volume.
%%
%% (The stale definition block that used to live here — the
%% private functions `setup_fuse_rootfs/1', `find_store_pid/0',
%% `manifest_path/1', `fuse_mount_path/1', `save_manifest/2',
%% `start_fuse_mount/3' — has moved intact.)

%% Signature verification (`maybe_verify_signature/1' +
%% `resolve_sig_path/1') lives in erlkoenig_ct_security.
