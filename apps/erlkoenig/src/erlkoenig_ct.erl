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
via Erlang Port (legacy) or Unix Domain Socket (new).
Drives the SPAWN -> GO -> EXITED sequence, handles kill/stop.

Communication modes:
  port   - Legacy: stdin/stdout pipe via open_port (default)
  socket - New: Unix Domain Socket at /run/erlkoenig/containers/<id>.sock

States:
  creating        -> Port/socket opened, SPAWN sent
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

%% API
-export([start_link/2,
         start_recovering/2,
         go/1,
         stop_container/1,
         kill/2,
         get_info/1,
         attach/2,
         send_input/2,
         resize/3]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3]).
%% Runtime-optional sibling modules (erlkoenig_fuse).
-dialyzer({no_missing_calls, [save_manifest/2, start_fuse_mount/3, cleanup_fuse/1]}).
%% erlkoenig_sig:verify uses throw() internally — dialyzer can't infer success path.
-dialyzer({no_match, [maybe_verify_signature/1]}).
%% build_info return type is extended dynamically by maybe_add_optional_fields.
-dialyzer({no_contracts, [build_info/2, maybe_add_optional_fields/3]}).

-export([creating/3, namespace_ready/3, starting/3,
         running/3, stopping/3, stopped/3, restarting/3,
         recovering/3, disconnected/3, failed/3]).

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

-record(ct_data, {
    id            :: binary(),
    binary_path   :: binary(),
    args          = [] :: [binary()],
    env           = [] :: [{binary(), binary()}],
    uid           = 0  :: non_neg_integer(),
    gid           = 0  :: non_neg_integer(),
    ip            :: inet:ip4_address() | undefined,
    zone          = default :: atom(),
    %% port field removed — socket mode only (no open_port)
    comm_mode     = socket :: socket,
    sock          :: gen_tcp:socket() | undefined,
    socket_path   :: binary() | undefined,
    os_pid        :: non_neg_integer() | undefined,
    netns_path    :: binary() | undefined,
    net_info      :: map() | undefined,
    started_at    :: integer() | undefined,
    exit_info     :: map() | undefined,
    error_reason  :: term() | undefined,
    from          :: gen_statem:from() | undefined,
    restart       = no_restart :: term(),
    restart_count = 0          :: non_neg_integer(),
    user_stopped  = false      :: boolean(),
    limits        = #{}        :: map(),
    seccomp       = 0          :: non_neg_integer(),
    caps_keep     = 0          :: non_neg_integer(),
    output        = undefined  :: pid() | undefined,
    name          = undefined  :: binary() | undefined,
    files         = #{}        :: #{binary() => binary()},
    handshake     = false      :: boolean(),
    pty           = false      :: boolean(),
    firewall      = #{}        :: map(),
    extra_opts    = #{}        :: map(),
    sig_path      = undefined  :: binary() | undefined,
    sig_verified  = false      :: boolean(),
    sig_meta      = undefined  :: map() | undefined,
    fuse_mount    = undefined  :: binary() | undefined,
    tmpfs_mounts  = []         :: [map()],
    volumes       = []         :: [map()]
}).

-define(SPAWN_TIMEOUT, application:get_env(erlkoenig, spawn_timeout, 30_000)).
-define(GO_TIMEOUT,    application:get_env(erlkoenig, go_timeout,    10_000)).
-define(STOP_TIMEOUT,  application:get_env(erlkoenig, stop_timeout,   5_000)).

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
    Restart = validate_restart(maps:get(restart, Opts, no_restart)),
    Data = #ct_data{
        id          = Id,
        binary_path = BinaryPath,
        args        = maps:get(args, Opts, []),
        env         = maps:get(env, Opts, []),
        uid         = maps:get(uid, Opts, 0),
        gid         = maps:get(gid, Opts, 0),
        ip          = maps:get(ip, Opts, undefined),
        zone        = maps:get(zone, Opts, default),
        comm_mode   = comm_mode(Opts),
        restart     = Restart,
        limits      = maps:get(limits, Opts, #{}),
        seccomp     = seccomp_profile_id(maps:get(seccomp, Opts, none)),
        caps_keep   = caps_to_mask(maps:get(caps, Opts, [])),
        output      = maps:get(output, Opts, undefined),
        name        = maps:get(name, Opts, undefined),
        files       = maps:get(files, Opts, #{}),
        pty         = maps:get(pty, Opts, false),
        firewall    = maps:get(firewall, Opts, #{}),
        sig_path    = maps:get(sig_path, Opts, undefined),
        volumes     = maps:get(volumes, Opts, []),
        extra_opts  = maps:without([args, env, uid, gid, ip, restart,
                                    limits, seccomp, caps, output, name,
                                    files, zone, pty, firewall, sig_path,
                                    signature_required, comm_mode, volumes], Opts)
    },
    {ok, creating, Data};

init({recover, ContainerId, #{socket_path := SocketPath, os_pid := OsPid} = Info}) ->
    proc_lib:set_label({erlkoenig_ct, ContainerId}),
    process_flag(trap_exit, true),
    Config = maps:get(config, Info, #{}),
    Data = #ct_data{
        id          = ContainerId,
        binary_path = maps:get(binary_path, Info, <<>>),
        comm_mode   = socket,
        socket_path = SocketPath,
        os_pid      = OsPid,
        ip          = maps:get(ip, Config, undefined),
        zone        = maps:get(zone, Config, default),
        restart     = validate_restart(maps:get(restart, Config, no_restart)),
        limits      = maps:get(limits, Config, #{}),
        seccomp     = seccomp_profile_id(maps:get(seccomp, Config, none)),
        caps_keep   = caps_to_mask(maps:get(caps, Config, [])),
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
    safe_sock_close(Sock),
    cleanup_socket_file(SockPath),
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
    Data2 = resolve_volumes(Data),
    creating_do_spawn(Data2);

%% Port mode: data from port
creating(info, {_Port, {data, Reply}}, #ct_data{comm_mode = socket,
                                                handshake = HS} = Data) ->
    creating_handle_rt_data(Reply, HS, Data);
creating(info, {tcp, Sock, Reply}, #ct_data{sock = Sock, comm_mode = socket,
                                             handshake = HS} = Data) ->
    creating_handle_rt_data(Reply, HS, Data);

creating(info, {_Port, {exit_status, Status}}, #ct_data{} = Data) ->
    {next_state, failed,
     Data#ct_data{error_reason = {port_died, Status}}};

creating(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    {next_state, failed,
     Data#ct_data{sock = undefined, error_reason = socket_closed}};

creating(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock} = Data) ->
    {next_state, failed,
     Data#ct_data{sock = undefined, error_reason = {socket_error, Reason}}};

creating(state_timeout, spawn_timeout, Data) ->
    {next_state, failed, Data#ct_data{error_reason = spawn_timeout}};

creating({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]}.

creating_do_spawn(#ct_data{comm_mode = port} = Data) ->
    RtBin = rt_path(),
    Port = open_port({spawn_executable, RtBin},
                     [{packet, 4}, binary, exit_status, use_stdio]),
    %% Protocol handshake
    port_command(Port, erlkoenig_proto:encode_handshake()),
    {keep_state, Data#ct_data{},
     [{state_timeout, ?SPAWN_TIMEOUT, spawn_timeout}]};
creating_do_spawn(#ct_data{comm_mode = socket, id = ContainerId} = Data) ->
    SocketPath = make_socket_path(ContainerId),
    ok = filelib:ensure_dir(binary_to_list(SocketPath)),
    %% Start C runtime via setsid in a background Erlang process.
    %% setsid gives the runtime its own session so it survives
    %% independently. File capabilities (setcap all=eip) on the
    %% binary provide full root caps after execve.
    %% The Erlang process blocks in os:cmd until the runtime exits.
    %% Monitoring: TCP socket (tcp_closed = runtime dead).
    RtBin = rt_path(),
    SockStr = binary_to_list(SocketPath),
    IdStr = binary_to_list(ContainerId),
    ShCmd = lists:flatten(io_lib:format(
        "exec setsid ~s --socket ~s --id ~s </dev/null 2>/dev/null",
        [RtBin, SockStr, IdStr])),
    erlang:spawn(fun() -> os:cmd(ShCmd) end),
    %% Wait for C runtime to bind the socket, then connect
    case wait_and_connect(SocketPath, 10000) of
        {ok, Sock} ->
            ok = inet:setopts(Sock, [binary, {packet, 4}, {active, true}]),
            %% Protocol handshake via socket
            ok = gen_tcp:send(Sock, erlkoenig_proto:encode_handshake()),
            {keep_state, Data#ct_data{
                sock = Sock,
                socket_path = SocketPath
            }, [{state_timeout, ?SPAWN_TIMEOUT, spawn_timeout}]};
        {error, Reason} ->
            {next_state, failed,
             Data#ct_data{error_reason = {socket_connect_failed, Reason}}}
    end.

creating_send_spawn(Data) ->
    DiskMB = disk_limit_mb(Data#ct_data.limits),
    DnsIp  = zone_dns_ip(Data#ct_data.zone),
    Flags  = case Data#ct_data.pty of
                 true  -> erlkoenig_proto:spawn_flag_pty();
                 false -> 0
             end,
    WireVolumes = [#{host => H, container => C,
                     opts => erlkoenig_proto:volume_opts(V)}
                   || #{host := H, container := C} = V <- Data#ct_data.volumes],
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
    send_to_rt(Cmd, Data).

creating_handle_rt_data(Reply, false = _Handshake, Data) ->
    %% First message: protocol handshake reply
    case erlkoenig_proto:check_handshake_reply(Reply) of
        ok ->
            case maybe_verify_signature(Data) of
                {ok, Data2} ->
                    creating_send_spawn(Data2),
                    {keep_state, Data2#ct_data{handshake = true}};
                {error, SigReason} ->
                    {next_state, failed,
                     Data#ct_data{error_reason = {signature_rejected, SigReason}}}
            end;
        {error, Reason} ->
            {next_state, failed,
             Data#ct_data{error_reason = Reason}}
    end;
creating_handle_rt_data(Reply, true = _Handshake, Data) ->
    %% Second message: SPAWN reply
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_container_pid, #{child_pid := Pid, netns_path := Ns}} ->
            {next_state, namespace_ready,
             Data#ct_data{os_pid = Pid, netns_path = Ns}};
        {ok, reply_error, #{code := Code, message := ErrMsg}} ->
            {next_state, failed,
             Data#ct_data{error_reason = {spawn_failed, Code, ErrMsg}}};
        Other ->
            {next_state, failed,
             Data#ct_data{error_reason = {unexpected_reply, Other}}}
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
    do_container_setup(Data);

namespace_ready(info, {_Port, {data, Reply}}, #ct_data{ comm_mode = port} = Data) ->
    namespace_ready_handle_data(Reply, Data);
namespace_ready(info, {tcp, Sock, Reply}, #ct_data{sock = Sock, comm_mode = socket} = Data) ->
    namespace_ready_handle_data(Reply, Data);

namespace_ready({call, From}, go, _Data) ->
    %% GO is now automatic after net setup. Just ack.
    {keep_state_and_data, [{reply, From, ok}]};

namespace_ready({call, _From}, stop_container, _Data) ->
    {keep_state_and_data, [postpone]};

namespace_ready({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(namespace_ready, Data)}]};

namespace_ready(info, {_Port, {exit_status, Status}}, #ct_data{} = Data) ->
    {next_state, failed,
     Data#ct_data{error_reason = {port_died, Status}}};

namespace_ready(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    {next_state, failed,
     Data#ct_data{sock = undefined, error_reason = socket_closed}};

namespace_ready(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock} = Data) ->
    {next_state, failed,
     Data#ct_data{sock = undefined, error_reason = {socket_error, Reason}}}.

namespace_ready_handle_data(Reply, Data) ->
    case erlkoenig_proto:decode(Reply) of
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

starting(info, {_Port, {data, Reply}}, #ct_data{ comm_mode = port} = Data) ->
    starting_handle_data(Reply, Data);
starting(info, {tcp, Sock, Reply}, #ct_data{sock = Sock, comm_mode = socket} = Data) ->
    starting_handle_data(Reply, Data);

starting(info, {_Port, {exit_status, Status}}, #ct_data{} = Data) ->
    Data2 = maybe_reply_go_error(Data, {port_died, Status}),
    {next_state, failed,
     Data2#ct_data{error_reason = {port_died, Status}}};

starting(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    Data2 = maybe_reply_go_error(Data, socket_closed),
    {next_state, failed,
     Data2#ct_data{sock = undefined, error_reason = socket_closed}};

starting(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock} = Data) ->
    Data2 = maybe_reply_go_error(Data, {socket_error, Reason}),
    {next_state, failed,
     Data2#ct_data{sock = undefined, error_reason = {socket_error, Reason}}};

starting(state_timeout, go_timeout, Data) ->
    Data2 = maybe_reply_go_error(Data, go_timeout),
    {next_state, failed, Data2#ct_data{error_reason = go_timeout}};

starting({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]}.

%% =================================================================
%% running - Container executing
%% =================================================================

running(enter, _OldState, Data) ->
    pg:join(erlkoenig_pg, erlkoenig_cts, self()),
    erlkoenig_events:notify({container_started, Data#ct_data.id, self()}),
    dns_register(Data),
    dets_register(Data),
    audit_volumes_mounted(Data),
    {keep_state, Data#ct_data{started_at = erlang:monotonic_time(millisecond)}};

running(info, {_Port, {data, Reply}}, #ct_data{ comm_mode = port} = Data) ->
    running_handle_data(Reply, Data);
running(info, {tcp, Sock, Reply}, #ct_data{sock = Sock, comm_mode = socket} = Data) ->
    running_handle_data(Reply, Data);

running(info, {_Port, {exit_status, _Status}}, #ct_data{} = Data) ->
    {next_state, stopped, Data};

running(info, {tcp_closed, Sock}, #ct_data{sock = Sock, comm_mode = socket} = Data) ->
    %% Socket lost but container may still be alive (C runtime survives)
    logger:warning("container ~s: socket closed, entering disconnected state",
                   [Data#ct_data.id]),
    {next_state, disconnected, Data#ct_data{sock = undefined}};

running(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock, comm_mode = socket} = Data) ->
    logger:error("container ~s: socket error ~p, entering disconnected state",
                 [Data#ct_data.id, Reason]),
    {next_state, disconnected, Data#ct_data{sock = undefined}};

running({call, From}, stop_container, Data) ->
    send_to_rt(erlkoenig_proto:encode_cmd_kill(15), Data),
    {next_state, stopping, Data#ct_data{from = From, user_stopped = true}};

running({call, From}, {kill, Signal}, Data) ->
    send_to_rt(erlkoenig_proto:encode_cmd_kill(Signal), Data),
    {next_state, stopping, Data,
     [{reply, From, ok}]};

running({call, From}, {attach, OutputPid}, Data) ->
    {keep_state, Data#ct_data{output = OutputPid}, [{reply, From, ok}]};

running({call, From}, {resize, Rows, Cols}, #ct_data{pty = true} = Data) ->
    send_to_rt(erlkoenig_proto:encode_cmd_resize(Rows, Cols), Data),
    {keep_state_and_data, [{reply, From, ok}]};

running({call, From}, {resize, _Rows, _Cols}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_pty}}]};

running({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(running, Data)}]};

running(cast, {send_input, InputData}, Data) ->
    send_to_rt(erlkoenig_proto:encode_cmd_stdin(InputData), Data),
    keep_state_and_data.

%% =================================================================
%% stopping - SIGTERM sent, waiting for exit
%% =================================================================

stopping(enter, _OldState, _Data) ->
    {keep_state_and_data, [{state_timeout, ?STOP_TIMEOUT, force_kill}]};

stopping(info, {_Port, {data, Reply}}, #ct_data{ comm_mode = port} = Data) ->
    stopping_handle_data(Reply, Data);
stopping(info, {tcp, Sock, Reply}, #ct_data{sock = Sock, comm_mode = socket} = Data) ->
    stopping_handle_data(Reply, Data);

stopping(info, {_Port, {exit_status, _Status}}, #ct_data{} = Data) ->
    Data2 = maybe_reply_stop(Data, ok),
    {next_state, stopped, Data2};

stopping(info, {tcp_closed, Sock}, #ct_data{sock = Sock} = Data) ->
    Data2 = maybe_reply_stop(Data, ok),
    {next_state, stopped, Data2#ct_data{sock = undefined}};

stopping(info, {tcp_error, Sock, _Reason}, #ct_data{sock = Sock} = Data) ->
    Data2 = maybe_reply_stop(Data, ok),
    {next_state, stopped, Data2#ct_data{sock = undefined}};

stopping(state_timeout, force_kill, Data) when Data#ct_data.sock =/= undefined ->
    send_to_rt(erlkoenig_proto:encode_cmd_kill(9), Data),
    {keep_state_and_data, [{state_timeout, ?STOP_TIMEOUT, give_up}]};

stopping(state_timeout, give_up, Data) ->
    Data2 = maybe_reply_stop(Data, {error, kill_timeout}),
    {next_state, failed, Data2#ct_data{error_reason = kill_timeout}};

stopping({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]}.

%% -- Data dispatch helpers (shared between port and socket modes) --

starting_handle_data(Reply, Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_ok, _} ->
            Data2 = maybe_reply_go(Data),
            {next_state, running, Data2};
        {ok, reply_exited, ExitInfo} ->
            %% Child exited before we got reply_ok
            Data2 = maybe_reply_go(Data),
            {next_state, stopped,
             Data2#ct_data{exit_info = ExitInfo}};
        {ok, reply_error, #{code := Code, message := ErrMsg}} ->
            Data2 = maybe_reply_go_error(Data, {go_failed, Code, ErrMsg}),
            {next_state, failed,
             Data2#ct_data{error_reason = {go_failed, Code, ErrMsg}}};
        {ok, reply_stdout, #{data := Chunk}} ->
            forward_output(stdout, Chunk, Data),
            keep_state_and_data;
        {ok, reply_stderr, #{data := Chunk}} ->
            forward_output(stderr, Chunk, Data),
            keep_state_and_data;
        Other ->
            {next_state, failed,
             Data#ct_data{error_reason = {unexpected_reply, Other}}}
    end.

running_handle_data(Reply, Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_exited, ExitInfo} ->
            {next_state, stopped, Data#ct_data{exit_info = ExitInfo}};
        {ok, reply_stdout, #{data := Chunk}} ->
            forward_output(stdout, Chunk, Data),
            keep_state_and_data;
        {ok, reply_stderr, #{data := Chunk}} ->
            forward_output(stderr, Chunk, Data),
            keep_state_and_data;
        {ok, reply_metrics_event, Event} ->
            erlkoenig_events:notify({container_metrics,
                                     Data#ct_data.id, Event}),
            keep_state_and_data;
        _Other ->
            keep_state_and_data
    end.

stopping_handle_data(Reply, Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_exited, ExitInfo} ->
            Data2 = maybe_reply_stop(Data, ok),
            {next_state, stopped, Data2#ct_data{exit_info = ExitInfo}};
        {ok, reply_stdout, #{data := Chunk}} ->
            forward_output(stdout, Chunk, Data),
            keep_state_and_data;
        {ok, reply_stderr, #{data := Chunk}} ->
            forward_output(stderr, Chunk, Data),
            keep_state_and_data;
        _Other ->
            keep_state_and_data
    end.

%% =================================================================
%% stopped - Container exited, check restart policy
%% =================================================================

stopped(enter, _OldState, Data) ->
    pg:leave(erlkoenig_pg, erlkoenig_cts, self()),
    firewall_remove(Data#ct_data.id),
    cleanup_fuse(Data),
    
    safe_sock_close(Data#ct_data.sock),
    cleanup_socket_file(Data#ct_data.socket_path),
    dns_unregister(Data),
    dets_unregister(Data),
    audit_volumes_released(Data),
    notify_stopped(Data),
    self() ! check_restart,
    {keep_state, Data#ct_data{sock = undefined,
                              fuse_mount = undefined}};

stopped(info, check_restart, Data) ->
    handle_check_restart(Data);

stopped({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(stopped, Data)}]};

stopped({call, From}, stop_container, Data) ->
    {keep_state, Data#ct_data{user_stopped = true}, [{reply, From, ok}]};

stopped({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, stopped}}]}.

%% =================================================================
%% restarting - Backoff wait before re-creating the container
%% =================================================================

restarting(enter, _OldState, Data) ->
    Backoff = backoff_ms(Data#ct_data.restart_count),
    erlkoenig_events:notify({container_restarting, Data#ct_data.id,
                           Data#ct_data.restart_count}),
    logger:info("container ~s restarting in ~pms (attempt ~p)",
                [Data#ct_data.id, Backoff, Data#ct_data.restart_count]),
    {keep_state_and_data, [{state_timeout, Backoff, do_restart}]};

restarting(state_timeout, do_restart, Data) ->
    %% Reset transient state, keep identity + config + restart count.
    {next_state, creating, Data#ct_data{
        os_pid       = undefined,
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
        tmpfs_mounts = []
    }};

restarting({call, From}, stop_container, Data) ->
    %% User stops during backoff: release IP, go to final stopped.
    Data2 = release_ip(Data),
    {next_state, stopped,
     Data2#ct_data{user_stopped = true, net_info = undefined},
     [{reply, From, ok}]};

restarting({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(restarting, Data)}]};

restarting({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, restarting}}]}.

%% =================================================================
%% failed - Error state, process stays alive for inspection
%% =================================================================

failed(enter, _OldState, Data) ->
    pg:leave(erlkoenig_pg, erlkoenig_cts, self()),
    firewall_remove(Data#ct_data.id),
    cleanup_fuse(Data),
    
    safe_sock_close(Data#ct_data.sock),
    cleanup_socket_file(Data#ct_data.socket_path),
    dns_unregister(Data),
    dets_unregister(Data),
    erlkoenig_events:notify({container_failed, Data#ct_data.id,
                           Data#ct_data.error_reason}),
    logger:error("container ~s failed: ~p",
                 [Data#ct_data.id, Data#ct_data.error_reason]),
    self() ! check_restart,
    {keep_state, Data#ct_data{sock = undefined,
                              fuse_mount = undefined}};

failed(info, check_restart, Data) ->
    handle_check_restart(Data);

failed({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(failed, Data)}]};

failed({call, From}, stop_container, Data) ->
    {keep_state, Data#ct_data{user_stopped = true}, [{reply, From, ok}]};

failed({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, failed}}]}.

%% =================================================================
%% recovering - Reconnecting to still-running container after crash
%% =================================================================

recovering(enter, _OldState, Data) ->
    %% Try to connect to the C runtime's socket
    case connect_to_runtime(Data) of
        {ok, Sock} ->
            %% Connected! Query status.
            NewData = Data#ct_data{sock = Sock},
            ok = gen_tcp:send(Sock, erlkoenig_proto:encode_cmd_query_status()),
            {keep_state, NewData};
        {error, _} ->
            %% Can't connect — C runtime is probably dead
            keep_state_and_data
    end;

recovering(info, {tcp, Sock, Reply}, #ct_data{sock = Sock} = Data) ->
    %% Got response from C runtime
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_status, #{state := State, child_pid := ChildPid}} when
                State > 0, ChildPid > 0 ->
            %% Container is still running! Transition to running.
            logger:info("container ~s recovered successfully (pid ~p)",
                        [Data#ct_data.id, ChildPid]),
            pg:join(erlkoenig_pg, erlkoenig_cts, self()),
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
     Data#ct_data{sock = undefined, error_reason = recovery_socket_closed}};

recovering(info, {tcp_error, Sock, Reason}, #ct_data{sock = Sock} = Data) ->
    logger:error("container ~s: socket error during recovery: ~p",
                 [Data#ct_data.id, Reason]),
    {next_state, failed,
     Data#ct_data{sock = undefined, error_reason = {recovery_socket_error, Reason}}};

recovering(state_timeout, recovery_timeout, Data) ->
    %% Couldn't recover in time
    logger:warning("container ~s: recovery timeout", [Data#ct_data.id]),
    {next_state, failed, Data#ct_data{error_reason = recovery_timeout}};

recovering({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(recovering, Data)}]};

recovering({call, From}, stop_container, Data) ->
    %% Kill via OS if possible
    kill_os_pid(Data#ct_data.os_pid),
    {next_state, stopped,
     Data#ct_data{user_stopped = true}, [{reply, From, ok}]};

recovering({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]}.

%% =================================================================
%% disconnected - Socket lost while running, attempting reconnect
%% =================================================================

disconnected(enter, _OldState, Data) ->
    %% Start reconnect timer
    logger:info("container ~s: disconnected, will attempt reconnect",
                [Data#ct_data.id]),
    {keep_state, Data, [{state_timeout, 1000, try_reconnect}]};

disconnected(state_timeout, try_reconnect, Data) ->
    case connect_to_runtime(Data) of
        {ok, Sock} ->
            NewData = Data#ct_data{sock = Sock},
            ok = gen_tcp:send(Sock, erlkoenig_proto:encode_cmd_query_status()),
            ok = inet:setopts(Sock, [{active, true}]),
            {next_state, recovering, NewData,
             [{state_timeout, 5000, recovery_timeout}]};
        {error, _} ->
            %% Retry in 1 second (up to 30 retries = 30s)
            {keep_state, Data, [{state_timeout, 1000, try_reconnect}]}
    end;

disconnected(info, {_Port, {exit_status, Status}}, #ct_data{} = Data) ->
    %% C runtime process died while disconnected
    logger:info("container ~s: C runtime died while disconnected (status ~p)",
                [Data#ct_data.id, Status]),
    {next_state, stopped, Data};

disconnected({call, From}, stop_container, Data) ->
    %% Can't send SIGTERM via socket, use kill directly
    kill_os_pid(Data#ct_data.os_pid),
    {next_state, stopped,
     Data#ct_data{user_stopped = true}, [{reply, From, ok}]};

disconnected({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(disconnected, Data)}]};

disconnected({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, disconnected}}]}.

%% =================================================================
%% Internal
%% =================================================================

%% -- Output forwarding --------------------------------------------

-spec forward_output(stdout | stderr, binary(), #ct_data{}) -> ok.
forward_output(_Stream, _Chunk, #ct_data{output = undefined}) ->
    ok;
forward_output(Stream, Chunk, #ct_data{output = Pid, id = Id}) when is_pid(Pid) ->
    Tag = case Stream of
              stdout -> container_stdout;
              stderr -> container_stderr
          end,
    Pid ! {Tag, self(), Id, Chunk},
    ok.

%% -- Restart logic ------------------------------------------------

%% -- Container setup (namespace_ready) --------------------------------

-spec do_container_setup(#ct_data{}) ->
    {next_state, atom(), #ct_data{}}.
do_container_setup(#ct_data{id = Id, os_pid = OsPid,
                            limits = Limits} = Data) ->
    %% Step 1: cgroup (before GO so the app process inherits it).
    HasCgroup = case setup_cgroup(Id, OsPid, Limits) of
        ok ->
            true;
        {error, CgReason} ->
            logger:warning("container ~s: cgroup setup failed: ~p "
                           "(continuing without limits)",
                           [Id, CgReason]),
            false
    end,
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
    case maybe_setup_rootfs(Data) of
        {ok, Data2} ->
            %% Step 3: network + files + GO.
            %% Note: uid_map/gid_map is written by the C runtime (erlkoenig_ns.c)
            %% immediately after clone, before replying with container_pid.
            %% By the time we get here, the child already has capabilities.
            do_container_net_setup(Data2);
        {error, FuseReason} ->
            _ = erlkoenig_cgroup:destroy(Id),
            {next_state, failed,
             Data#ct_data{error_reason = {rootfs_setup_failed, FuseReason}}}
    end.

-spec do_container_net_setup(#ct_data{}) ->
    {next_state, atom(), #ct_data{}}.
do_container_net_setup(#ct_data{id = Id, ip = Ip,
                                os_pid = OsPid, zone = Zone} = Data) ->
    %% erlkoenig_net needs a handle to send CMD_NET_SETUP to the C runtime.
    %% In socket mode, we temporarily set active=false for synchronous recv.
    Handle = rt_io_handle(Data),
    ok = maybe_set_active(Data, false),
    NetResult = case Ip of
        undefined -> erlkoenig_net:setup_container_net(Handle, Id, OsPid, Zone);
        _         -> erlkoenig_net:setup_container_net(Handle, Id, OsPid, Ip, Zone)
    end,
    ok = maybe_set_active(Data, true),
    case NetResult of
        {ok, NetInfo} ->
            firewall_add(Id, NetInfo, Data#ct_data.firewall, Data#ct_data.name),
            write_container_files(Data, Data#ct_data.files),
            send_to_rt(erlkoenig_proto:encode_cmd_go(), Data),
            Data2 = case Ip of
                undefined -> Data#ct_data{net_info = NetInfo,
                                          ip = maps:get(ip, NetInfo)};
                _         -> Data#ct_data{net_info = NetInfo}
            end,
            {next_state, starting, Data2};
        {error, Reason} ->
            _ = erlkoenig_cgroup:destroy(Id),
            {next_state, failed,
             Data#ct_data{error_reason = {net_setup_failed, Reason}}}
    end.

%% -- Restart logic ------------------------------------------------

-spec handle_check_restart(#ct_data{}) ->
    {next_state, atom(), #ct_data{}} | {keep_state, #ct_data{}}.
handle_check_restart(Data) ->
    _ = teardown_veth(Data),
    _ = destroy_cgroup(Data),
    Data2 = Data#ct_data{net_info = undefined},
    case should_restart(Data2) of
        true ->
            {next_state, restarting,
             Data2#ct_data{restart_count = Data2#ct_data.restart_count + 1}};
        false ->
            Data3 = release_ip(Data2),
            {keep_state, Data3}
    end.

-spec should_restart(#ct_data{}) -> boolean().
should_restart(#ct_data{user_stopped = true}) -> false;
should_restart(#ct_data{restart = no_restart}) -> false;
should_restart(Data) ->
    {Strategy, Max} = normalize_restart(Data#ct_data.restart),
    WithinLimit = case Max of
        infinity -> true;
        N        -> Data#ct_data.restart_count < N
    end,
    case Strategy of
        always     -> WithinLimit;
        on_failure -> WithinLimit andalso is_failure_exit(Data)
    end.

-spec normalize_restart(term()) -> {always | on_failure | no_restart, infinity | non_neg_integer()}.
normalize_restart(always)          -> {always, infinity};
normalize_restart(on_failure)      -> {on_failure, infinity};
normalize_restart({always, N})     -> {always, N};
normalize_restart({on_failure, N}) -> {on_failure, N};
normalize_restart(_)               -> {no_restart, 0}.

-spec is_failure_exit(#ct_data{}) -> boolean().
is_failure_exit(#ct_data{exit_info = #{exit_code := 0, term_signal := 0}}) ->
    false;
is_failure_exit(_) ->
    true.

-spec validate_restart(term()) -> erlkoenig:restart_policy().
validate_restart(no_restart)                            -> no_restart;
validate_restart(always)                                -> always;
validate_restart(on_failure)                            -> on_failure;
validate_restart({always, N}) when is_integer(N), N > 0 -> {always, N};
validate_restart({on_failure, N}) when is_integer(N), N > 0 -> {on_failure, N};
validate_restart(Other) -> error({invalid_restart_policy, Other}).

-spec backoff_ms(integer()) -> pos_integer().
backoff_ms(N) when N =< 0 -> 1000;
backoff_ms(N)              -> min(30_000, 1000 bsl min(N - 1, 4)).

%% -- Event notifications ------------------------------------------

-spec notify_stopped(#ct_data{}) -> ok.
notify_stopped(#ct_data{id = Id, exit_info = ExitInfo}) ->
    erlkoenig_events:notify({container_stopped, Id, ExitInfo}),
    %% Detect OOM-Kill via cgroup memory.events (authoritative).
    %% Fallback to signal heuristic if cgroup check fails.
    OOM = case erlkoenig_cgroup:was_oom_killed(Id) of
        true  -> true;
        false -> maps:get(term_signal, ExitInfo, 0) =:= 9
    end,
    case OOM of
        true  -> erlkoenig_events:notify({container_oom, Id});
        false -> ok
    end.

%% -- Container files ----------------------------------------------

-spec write_container_files(#ct_data{}, #{binary() => binary()}) -> ok.
write_container_files(_Data, Files) when map_size(Files) =:= 0 -> ok;
write_container_files(CtData, Files) ->
    maps:foreach(fun(Path, FileContent) ->
        Cmd = erlkoenig_proto:encode_cmd_write_file(Path, 8#644, FileContent),
        send_to_rt(Cmd, CtData)
    end, Files).

%% -- DNS registration ---------------------------------------------

-spec dns_register(#ct_data{}) -> ok.
dns_register(#ct_data{ip = undefined}) -> ok;
dns_register(#ct_data{name = Name, id = Id, ip = Ip, zone = Zone}) ->
    DnsName = case Name of
        undefined -> Id;
        _         -> Name
    end,
    try
        DnsPid = erlkoenig_zone:dns(Zone),
        gen_server:call(DnsPid, {register, DnsName, Ip})
    catch Class:Reason ->
        logger:warning("container ~s: DNS register failed: ~p:~p",
                       [Id, Class, Reason])
    end,
    ok.

-spec dns_unregister(#ct_data{}) -> ok.
dns_unregister(#ct_data{ip = undefined}) -> ok;
dns_unregister(#ct_data{name = Name, id = Id, zone = Zone}) ->
    DnsName = case Name of
        undefined -> Id;
        _         -> Name
    end,
    try
        DnsPid = erlkoenig_zone:dns(Zone),
        gen_server:call(DnsPid, {unregister, DnsName})
    catch Class:Reason ->
        logger:warning("container ~s: DNS unregister failed: ~p:~p",
                       [Id, Class, Reason])
    end,
    ok.

%% -- DETS state persistence ----------------------------------------

-spec dets_register(#ct_data{}) -> ok.
dets_register(#ct_data{id = Id, os_pid = OsPid, socket_path = SocketPath,
                        ip = Ip, zone = Zone, binary_path = BinaryPath,
                        comm_mode = CommMode, net_info = NetInfo,
                        firewall = Firewall, restart = Restart,
                        limits = Limits, seccomp = Seccomp,
                        caps_keep = CapsKeep, name = Name,
                        args = Args, env = Env, uid = Uid, gid = Gid,
                        extra_opts = ExtraOpts, volumes = Volumes} = _Data) ->
    case whereis(erlkoenig_node_state) of
        undefined -> ok;
        _ ->
            VethHost = case NetInfo of
                #{host_veth := VH} -> VH;
                _ -> undefined
            end,
            VethContainer = case NetInfo of
                #{container_veth := VC} -> VC;
                _ -> undefined
            end,
            Bridge = zone_bridge_name(Zone),
            CgroupPath = cgroup_path_for_id(Id),
            Config = #{
                args => Args,
                env => Env,
                uid => Uid,
                gid => Gid,
                zone => Zone,
                restart => Restart,
                limits => Limits,
                seccomp => Seccomp,
                caps_keep => CapsKeep,
                name => Name,
                firewall => Firewall,
                extra_opts => ExtraOpts,
                volumes => Volumes
            },
            Info = #{
                os_pid => OsPid,
                socket_path => SocketPath,
                ip => Ip,
                netns => netns_path(OsPid),
                cgroup => CgroupPath,
                veth_host => VethHost,
                veth_container => VethContainer,
                bridge => Bridge,
                zone => Zone,
                binary_path => BinaryPath,
                config => Config,
                started_at => erlang:system_time(second),
                comm_mode => CommMode
            },
            try erlkoenig_node_state:register_container(Id, Info)
            catch _:_ -> ok
            end
    end,
    ok.

-spec dets_unregister(#ct_data{}) -> ok.
dets_unregister(#ct_data{id = Id}) ->
    case whereis(erlkoenig_node_state) of
        undefined -> ok;
        _ ->
            try erlkoenig_node_state:unregister_container(Id)
            catch _:_ -> ok
            end
    end,
    ok.

-spec netns_path(non_neg_integer() | undefined) -> binary() | undefined.
netns_path(undefined) -> undefined;
netns_path(Pid) when is_integer(Pid), Pid > 0 ->
    list_to_binary("/proc/" ++ integer_to_list(Pid) ++ "/ns/net");
netns_path(_) -> undefined.

-spec zone_bridge_name(atom()) -> binary().
zone_bridge_name(default) ->
    case application:get_env(erlkoenig, bridge_name, <<"erlkoenig_br0">>) of
        Bin when is_binary(Bin) -> Bin;
        Str when is_list(Str) -> list_to_binary(Str)
    end;
zone_bridge_name(ZoneName) ->
    try
        #{bridge := Bridge} = erlkoenig_zone:zone_config(ZoneName),
        Bridge
    catch _:_ ->
        <<"erlkoenig_br0">>
    end.

-spec cgroup_path_for_id(binary()) -> binary().
cgroup_path_for_id(Id) ->
    try
        case erlkoenig_cgroup:path(Id) of
            {ok, Path} -> list_to_binary(Path);
            _ -> <<>>
        end
    catch _:_ ->
        <<>>
    end.

%% -- Socket cleanup -----------------------------------------------

-spec safe_sock_close(gen_tcp:socket() | undefined) -> ok.
safe_sock_close(undefined) -> ok;
safe_sock_close(Sock) ->
    gen_tcp:close(Sock),
    ok.

-spec cleanup_socket_file(binary() | undefined) -> ok.
cleanup_socket_file(undefined) -> ok;
cleanup_socket_file(Path) ->
    _ = file:delete(Path),
    ok.

%% -- Communication abstraction ------------------------------------

-doc "Send data to C runtime via socket.".
-spec send_to_rt(iodata(), #ct_data{}) -> ok.
send_to_rt(Bin, #ct_data{sock = Sock}) when Sock =/= undefined ->
    ok = gen_tcp:send(Sock, Bin),
    ok;
send_to_rt(_Bin, _Data) ->
    ok.

-doc "Return the I/O handle for external modules (e.g. erlkoenig_net).".
-spec rt_io_handle(#ct_data{}) -> {socket, gen_tcp:socket()} | undefined.
rt_io_handle(#ct_data{sock = Sock}) when Sock =/= undefined ->
    {socket, Sock};
rt_io_handle(_) ->
    undefined.

-doc "Temporarily toggle socket active mode. No-op for port mode.".
-spec maybe_set_active(#ct_data{}, boolean()) -> ok.
maybe_set_active(#ct_data{comm_mode = socket, sock = Sock}, Active)
  when Sock =/= undefined ->
    ok = inet:setopts(Sock, [{active, Active}]);
maybe_set_active(_, _) ->
    ok.

%% -- Socket helpers -----------------------------------------------

-doc "Determine communication mode from opts or application env.".
-spec comm_mode(map()) -> port | socket.
comm_mode(Opts) ->
    maps:get(comm_mode, Opts,
             application:get_env(erlkoenig, comm_mode, port)).

-doc "Get the socket directory from application config.".
-spec socket_dir() -> binary().
socket_dir() ->
    case application:get_env(erlkoenig, socket_dir, "/run/erlkoenig/") of
        Path when is_list(Path) -> list_to_binary(Path);
        Path when is_binary(Path) -> Path
    end.

-doc "Generate the socket path for a container. Must match erlkoenig-rt@.service.".
-spec make_socket_path(binary()) -> binary().
make_socket_path(ContainerId) ->
    Dir = socket_dir(),
    filename:join(Dir, <<ContainerId/binary, ".sock">>).

-doc "Wait for a Unix socket to appear and connect.".
%% Polls every 50ms until the socket is connectable or timeout.
-spec wait_and_connect(binary(), non_neg_integer()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
wait_and_connect(SocketPath, Timeout) ->
    wait_and_connect(SocketPath, Timeout, 50).

-spec wait_and_connect(binary(), integer(), pos_integer()) ->
    {ok, gen_tcp:socket()} | {error, term()}.
wait_and_connect(_SocketPath, Timeout, _Interval) when Timeout =< 0 ->
    {error, timeout};
wait_and_connect(SocketPath, Timeout, Interval) ->
    SockPathStr = binary_to_list(SocketPath),
    case gen_tcp:connect({local, SockPathStr}, 0,
                         [binary, {packet, 4}, {active, false}], 1000) of
        {ok, Sock} ->
            {ok, Sock};
        {error, enoent} ->
            timer:sleep(Interval),
            wait_and_connect(SocketPath, Timeout - Interval, Interval);
        {error, econnrefused} ->
            timer:sleep(Interval),
            wait_and_connect(SocketPath, Timeout - Interval, Interval);
        {error, Reason} ->
            logger:warning("wait_and_connect: ~s failed: ~p (retrying)",
                          [SockPathStr, Reason]),
            timer:sleep(Interval),
            wait_and_connect(SocketPath, Timeout - Interval, Interval)
    end.

-doc "Try to connect to a still-running C runtime's socket.".
-spec connect_to_runtime(#ct_data{}) ->
    {ok, gen_tcp:socket()} | {error, term()}.
connect_to_runtime(#ct_data{socket_path = undefined}) ->
    {error, no_socket_path};
connect_to_runtime(#ct_data{socket_path = SocketPath}) ->
    SockPathStr = binary_to_list(SocketPath),
    case gen_tcp:connect({local, SockPathStr}, 0,
                         [binary, {packet, 4}, {active, true}], 3000) of
        {ok, Sock} -> {ok, Sock};
        {error, _} = Err -> Err
    end.

-doc "Kill a process by OS PID (used when socket is unavailable).".
-spec kill_os_pid(non_neg_integer() | undefined) -> ok.
kill_os_pid(undefined) -> ok;
kill_os_pid(Pid) when is_integer(Pid), Pid > 0 ->
    _ = os:cmd("kill -15 " ++ integer_to_list(Pid)),
    ok;
kill_os_pid(_) -> ok.

%% -- Firewall (direct nft integration) ----------------------------

-spec firewall_add(binary(), map(), map(), binary() | undefined) -> ok.
firewall_add(ContainerId, #{ip := Ip, host_veth := Veth} = _NetInfo, FwTerm, Name) ->
    Ports = [],  %% Port mappings handled via firewall term
    case erlkoenig_firewall_nft:add_container(ContainerId, Ip, Veth, Ports, FwTerm, Name) of
        ok -> ok;
        {error, Reason} ->
            logger:warning("firewall: failed to create chain for ~s: ~p",
                           [ContainerId, Reason])
    end,
    ok.

-spec firewall_remove(binary()) -> ok.
firewall_remove(ContainerId) ->
    _ = erlkoenig_firewall_nft:remove_container(ContainerId),
    ok.

%% -- Network teardown ---------------------------------------------

-spec teardown_veth(#ct_data{}) -> ok.
teardown_veth(#ct_data{net_info = undefined}) ->
    ok;
teardown_veth(#ct_data{net_info = NetInfo}) ->
    erlkoenig_net:teardown_container_veth(NetInfo).

-spec release_ip(#ct_data{}) -> #ct_data{}.
release_ip(#ct_data{ip = undefined} = Data) ->
    Data;
release_ip(#ct_data{ip = Ip} = Data) ->
    erlkoenig_ip_pool:release(Ip),
    Data#ct_data{ip = undefined}.

-spec disk_limit_mb(map()) -> non_neg_integer().
disk_limit_mb(#{disk := Bytes}) when is_integer(Bytes), Bytes > 0 ->
    max(1, Bytes div (1024 * 1024));
disk_limit_mb(_) ->
    0.

-doc "Get the DNS IP for a zone as a 32-bit network-order integer.".
%% The DNS server runs on the zone's gateway IP.
-spec zone_dns_ip(atom()) -> non_neg_integer().
zone_dns_ip(default) ->
    ip4_to_u32(application:get_env(erlkoenig, gateway, {10, 0, 0, 1}));
zone_dns_ip(ZoneName) ->
    #{gateway := Gw} = erlkoenig_zone:zone_config(ZoneName),
    ip4_to_u32(Gw).

-spec ip4_to_u32(inet:ip4_address()) -> non_neg_integer().
ip4_to_u32({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

-spec seccomp_profile_id(erlkoenig:seccomp_profile() | non_neg_integer()) -> non_neg_integer().
seccomp_profile_id(none)    -> 0;
seccomp_profile_id(default) -> 1;
seccomp_profile_id(strict)  -> 2;
seccomp_profile_id(network) -> 3;
seccomp_profile_id(N) when is_integer(N), N >= 0, N =< 255 -> N;
seccomp_profile_id(Other) -> error({invalid_seccomp_profile, Other}).

-spec seccomp_profile_name(non_neg_integer()) -> erlkoenig:seccomp_profile() | non_neg_integer().
seccomp_profile_name(0) -> none;
seccomp_profile_name(1) -> default;
seccomp_profile_name(2) -> strict;
seccomp_profile_name(3) -> network;
seccomp_profile_name(N) -> N.

%% =================================================================
%% Capabilities: atom list <-> 64-bit bitmask
%% =================================================================

-spec cap_bit(erlkoenig:capability()) -> 0..40.
cap_bit(chown)              -> 0;
cap_bit(dac_override)       -> 1;
cap_bit(dac_read_search)    -> 2;
cap_bit(fowner)             -> 3;
cap_bit(fsetid)             -> 4;
cap_bit(kill)               -> 5;
cap_bit(setgid)             -> 6;
cap_bit(setuid)             -> 7;
cap_bit(setpcap)            -> 8;
cap_bit(linux_immutable)    -> 9;
cap_bit(net_bind_service)   -> 10;
cap_bit(net_broadcast)      -> 11;
cap_bit(net_admin)          -> 12;
cap_bit(net_raw)            -> 13;
cap_bit(ipc_lock)           -> 14;
cap_bit(ipc_owner)          -> 15;
cap_bit(sys_module)         -> 16;
cap_bit(sys_rawio)          -> 17;
cap_bit(sys_chroot)         -> 18;
cap_bit(sys_ptrace)         -> 19;
cap_bit(sys_pacct)          -> 20;
cap_bit(sys_admin)          -> 21;
cap_bit(sys_boot)           -> 22;
cap_bit(sys_nice)           -> 23;
cap_bit(sys_resource)       -> 24;
cap_bit(sys_time)           -> 25;
cap_bit(sys_tty_config)     -> 26;
cap_bit(mknod)              -> 27;
cap_bit(lease)              -> 28;
cap_bit(audit_write)        -> 29;
cap_bit(audit_control)      -> 30;
cap_bit(setfcap)            -> 31;
cap_bit(mac_override)       -> 32;
cap_bit(mac_admin)          -> 33;
cap_bit(syslog)             -> 34;
cap_bit(wake_alarm)         -> 35;
cap_bit(block_suspend)      -> 36;
cap_bit(audit_read)         -> 37;
cap_bit(perfmon)            -> 38;
cap_bit(bpf)                -> 39;
cap_bit(checkpoint_restore) -> 40;
cap_bit(Other) -> error({unknown_capability, Other}).

-spec caps_to_mask([erlkoenig:capability()]) -> non_neg_integer().
caps_to_mask([]) -> 0;
caps_to_mask(Caps) when is_list(Caps) ->
    lists:foldl(fun(Cap, Acc) ->
        Acc bor (1 bsl cap_bit(Cap))
    end, 0, Caps).

-spec mask_to_caps(non_neg_integer()) -> [erlkoenig:capability()].
mask_to_caps(0) -> [];
mask_to_caps(Mask) ->
    AllCaps = [chown, dac_override, dac_read_search, fowner, fsetid,
               kill, setgid, setuid, setpcap, linux_immutable,
               net_bind_service, net_broadcast, net_admin, net_raw,
               ipc_lock, ipc_owner, sys_module, sys_rawio, sys_chroot,
               sys_ptrace, sys_pacct, sys_admin, sys_boot, sys_nice,
               sys_resource, sys_time, sys_tty_config, mknod, lease,
               audit_write, audit_control, setfcap, mac_override,
               mac_admin, syslog, wake_alarm, block_suspend, audit_read,
               perfmon, bpf, checkpoint_restore],
    [Cap || Cap <- AllCaps, Mask band (1 bsl cap_bit(Cap)) =/= 0].

-spec destroy_cgroup(#ct_data{}) -> ok | {error, term()}.
destroy_cgroup(#ct_data{id = Id}) ->
    erlkoenig_cgroup:destroy(Id).

-spec setup_cgroup(binary(), non_neg_integer(), map()) -> ok | {error, term()}.
setup_cgroup(Id, OsPid, Limits) ->
    maybe
        ok ?= erlkoenig_cgroup:create(Id),
        ok ?= erlkoenig_cgroup:attach(Id, OsPid),
        case map_size(Limits) =:= 0 of
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
            case sync_rt_command(Data, Cmd, 5000) of
                {ok, Reply} ->
                    handle_setup_reply(Reply, Id, "device filter");
                timeout ->
                    logger:warning("container ~s: device filter timeout", [Id])
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
            case sync_rt_command(Data, Cmd, 5000) of
                {ok, Reply} ->
                    handle_setup_reply(Reply, Id, "eBPF metrics");
                timeout ->
                    logger:warning("container ~s: eBPF metrics timeout", [Id])
            end;
        {error, _} ->
            ok
    end,
    ok.

-doc "Send a command and synchronously wait for the reply.".
-spec sync_rt_command(#ct_data{}, iodata(), non_neg_integer()) ->
    {ok, binary()} | timeout.
sync_rt_command(#ct_data{sock = Sock}, Cmd, Timeout) when Sock =/= undefined ->
    ok = inet:setopts(Sock, [{active, false}]),
    ok = gen_tcp:send(Sock, Cmd),
    Result = case gen_tcp:recv(Sock, 0, Timeout) of
        {ok, Reply} -> {ok, Reply};
        {error, _}  -> timeout
    end,
    ok = inet:setopts(Sock, [{active, true}]),
    Result.

-spec handle_setup_reply(binary(), binary(), string()) -> ok.
handle_setup_reply(Reply, Id, What) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_ok, _} ->
            logger:debug("container ~s: ~s attached", [Id, What]);
        {ok, reply_error, #{code := Code, message := Msg}} ->
            logger:warning("container ~s: ~s failed: ~p ~s (continuing without)",
                           [Id, What, Code, Msg])
    end.

-spec make_id() -> erlkoenig:container_id().
make_id() ->
    <<A:32, B:16, C:16, D:16, E:48>> = crypto:strong_rand_bytes(16),
    list_to_binary(io_lib:format(
      "~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b",
      [A, B, C band 16#0fff bor 16#4000,
       D band 16#3fff bor 16#8000, E])).

-spec rt_path() -> string().
rt_path() ->
    case application:get_env(erlkoenig, rt_path, auto) of
        auto -> find_rt();
        Path -> Path
    end.

-spec find_rt() -> string().
find_rt() ->
    Candidates = [
        fun() -> os:find_executable("erlkoenig_rt") end,
        fun() -> check_path("/usr/lib/erlkoenig/erlkoenig_rt") end,
        fun() -> check_path("/opt/erlkoenig/rt/erlkoenig_rt") end,
        fun() -> check_priv_dir() end,
        fun() -> check_build_dir() end
    ],
    find_first(Candidates).

-spec find_first([fun(() -> false | string())]) -> string().
find_first([]) ->
    error(erlkoenig_rt_not_found);
find_first([F | Rest]) ->
    case F() of
        false -> find_first(Rest);
        Path  -> Path
    end.

-spec check_path(string()) -> false | string().
check_path(Path) ->
    case filelib:is_regular(Path) of
        true  -> Path;
        false -> false
    end.

-spec check_priv_dir() -> false | string().
check_priv_dir() ->
    try code:priv_dir(erlkoenig) of
        Dir ->
            Path = filename:join(Dir, "erlkoenig_rt"),
            check_path(Path)
    catch
        error:bad_name -> false
    end.

-spec check_build_dir() -> false | string().
check_build_dir() ->
    Ebin = filename:dirname(code:which(?MODULE)),
    ProjectRoot = filename:join([Ebin, "..", "..", "..", "..", ".."]),
    Path = filename:absname(filename:join(ProjectRoot, "build/release/erlkoenig_rt")),
    check_path(Path).

%% -- Volume audit -------------------------------------------------

-spec audit_volumes_mounted(#ct_data{}) -> ok.
audit_volumes_mounted(#ct_data{volumes = []}) -> ok;
audit_volumes_mounted(#ct_data{id = Id, name = Name, volumes = Volumes}) ->
    ContainerName = case Name of undefined -> Id; N -> N end,
    lists:foreach(fun(#{host := Host, container := ContPath,
                        persist := Persist, read_only := RO}) ->
        erlkoenig_audit:log(#{
            type => volume_mounted,
            subject => ContainerName,
            result => ok,
            details => #{
                persist => Persist,
                host => Host,
                container_path => ContPath,
                read_only => RO
            }
        })
    end, Volumes),
    ok.

-spec audit_volumes_released(#ct_data{}) -> ok.
audit_volumes_released(#ct_data{volumes = []}) -> ok;
audit_volumes_released(#ct_data{id = Id, name = Name, volumes = Volumes}) ->
    ContainerName = case Name of undefined -> Id; N -> N end,
    lists:foreach(fun(#{persist := Persist}) ->
        erlkoenig_audit:log(#{
            type => volume_released,
            subject => ContainerName,
            result => ok,
            details => #{persist => Persist}
        })
    end, Volumes),
    ok.

%% -- Volume resolution -------------------------------------------

-spec resolve_volumes(#ct_data{}) -> #ct_data{}.
resolve_volumes(#ct_data{volumes = []} = Data) ->
    Data;
resolve_volumes(#ct_data{volumes = DslVolumes, name = Name, id = Id} = Data) ->
    ContainerName = case Name of
        undefined -> Id;
        N -> N
    end,
    case erlkoenig_volume:resolve(ContainerName, DslVolumes) of
        {ok, Resolved} ->
            lists:foreach(fun(#{host := HostPath}) ->
                case erlkoenig_volume:ensure_volume_dir(HostPath) of
                    ok -> ok;
                    {error, Reason} ->
                        logger:warning("container ~s: failed to create volume dir ~s: ~p",
                                       [Id, HostPath, Reason])
                end
            end, Resolved),
            Data#ct_data{volumes = Resolved};
        {error, Reason} ->
            logger:error("container ~s: volume resolution failed: ~p", [Id, Reason]),
            Data
    end.

-spec build_info(atom(), #ct_data{}) -> erlkoenig:container_info().
build_info(State, Data) ->
    Info = #{
        id            => Data#ct_data.id,
        state         => State,
        binary        => Data#ct_data.binary_path,
        os_pid        => Data#ct_data.os_pid,
        netns_path    => Data#ct_data.netns_path,
        restart       => Data#ct_data.restart,
        restart_count => Data#ct_data.restart_count,
        limits        => Data#ct_data.limits,
        seccomp       => seccomp_profile_name(Data#ct_data.seccomp),
        caps          => mask_to_caps(Data#ct_data.caps_keep),
        name          => Data#ct_data.name,
        zone          => Data#ct_data.zone,
        args          => Data#ct_data.args,
        ports         => maps:get(ports, Data#ct_data.extra_opts, []),
        volumes       => Data#ct_data.volumes
    },
    maybe_add_optional_fields(State, Data, Info).

-spec maybe_add_optional_fields(atom(), #ct_data{}, map()) -> erlkoenig:container_info().
maybe_add_optional_fields(State, Data, Info0) ->
    Info1 = maybe_put(net_info, Data#ct_data.net_info, Info0),
    Info2 = maybe_put(exit_info, Data#ct_data.exit_info, Info1),
    Info3 = maybe_put(error, Data#ct_data.error_reason, Info2),
    maybe_add_stats(State, Data#ct_data.id, Info3).

-spec maybe_put(atom(), term(), map()) -> map().
maybe_put(_Key, undefined, Map) -> Map;
maybe_put(Key, Value, Map)      -> Map#{Key => Value}.

-spec maybe_add_stats(atom(), binary(), map()) -> map().
maybe_add_stats(running, Id, Info) ->
    case erlkoenig_cgroup:read_stats(Id) of
        {ok, Stats} when map_size(Stats) > 0 -> Info#{stats => Stats};
        _                                     -> Info
    end;
maybe_add_stats(_State, _Id, Info) ->
    Info.

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

%% --- FUSE rootfs setup / cleanup ---

-doc "Build and mount FUSE rootfs if a rootfs config is present.".
%% The rootfs config lives in extra_opts (put there by the DSL compiler).
%% If no rootfs config → legacy mode (no FUSE), returns Data unchanged.
-spec maybe_setup_rootfs(#ct_data{}) -> {ok, #ct_data{}} | {error, term()}.
maybe_setup_rootfs(Data) ->
    case maps:get(rootfs, Data#ct_data.extra_opts, undefined) of
        undefined ->
            %% No rootfs spec → legacy mode (no FUSE)
            {ok, Data};
        _RootfsSpec ->
            setup_fuse_rootfs(Data)
    end.

-spec setup_fuse_rootfs(#ct_data{}) -> {ok, #ct_data{}} | {error, term()}.
setup_fuse_rootfs(Data) ->
    ContainerId = Data#ct_data.id,
    ExtraOpts = Data#ct_data.extra_opts,
    RootfsConfig = #{
        rootfs => maps:get(rootfs, ExtraOpts, #{}),
        binary => Data#ct_data.binary_path,
        seccomp => maps:get(rootfs_seccomp, ExtraOpts, undefined)
    },
    case find_store_pid() of
        undefined ->
            logger:warning("erlkoenig_fuse_store not available, "
                           "skipping FUSE rootfs for ~s", [ContainerId]),
            {ok, Data};
        Pid ->
            BuildOpts = case Data#ct_data.name of
                undefined -> #{};
                Name      -> #{artifact_name => Name}
            end,
            maybe
                {ok, #{manifest := Manifest,
                       tmpfs_mounts := TmpfsMounts}} ?=
                    case erlkoenig_rootfs_builder:build(RootfsConfig, Pid, BuildOpts) of
                        {ok, _} = Ok -> Ok;
                        {error, Reason1} ->
                            logger:error("Failed to build rootfs for ~s: ~p",
                                         [ContainerId, Reason1]),
                            {error, {rootfs_build_failed, Reason1}}
                    end,
                %% Save manifest
                ManifestPath = manifest_path(ContainerId),
                save_manifest(Manifest, ManifestPath),
                %% Start FUSE mount
                MountPath = fuse_mount_path(ContainerId),
                _ = filelib:ensure_path(MountPath),
                {ok, _MountPid} ?=
                    case start_fuse_mount(ContainerId, Manifest, MountPath) of
                        {ok, _} = Ok2 -> Ok2;
                        {error, Reason2} ->
                            logger:error("Failed to mount FUSE for ~s: ~p",
                                         [ContainerId, Reason2]),
                            {error, {fuse_mount_failed, Reason2}}
                    end,
                MountBin = unicode:characters_to_binary(MountPath),
                logger:info("FUSE rootfs mounted for ~s at ~s",
                            [ContainerId, MountPath]),
                {ok, Data#ct_data{
                    fuse_mount = MountBin,
                    tmpfs_mounts = TmpfsMounts
                }}
            else
                {error, _} = Err -> Err
            end
    end.

-spec find_store_pid() -> pid() | undefined.
find_store_pid() ->
    whereis(erlkoenig_fuse_store).

-spec manifest_path(binary()) -> string().
manifest_path(ContainerId) ->
    Dir = application:get_env(erlkoenig, manifest_dir,
                              "/var/lib/erlkoenig/manifests"),
    _ = filelib:ensure_dir(filename:join(Dir, "x")),
    filename:join(Dir, binary_to_list(ContainerId) ++ ".manifest").

-spec fuse_mount_path(binary()) -> string().
fuse_mount_path(ContainerId) ->
    Dir = application:get_env(erlkoenig, fuse_mount_dir,
                              "/run/erlkoenig/mounts"),
    _ = filelib:ensure_dir(filename:join(Dir, "x")),
    filename:join(Dir, binary_to_list(ContainerId)).

-spec save_manifest(term(), string()) -> ok.
save_manifest(Manifest, Path) ->
    try
        erlkoenig_fuse_manifest:save(Manifest, Path)
    catch
        error:undef ->
            logger:warning("erlkoenig_fuse_manifest not available, "
                           "skipping manifest save"),
            ok;
        _:Reason ->
            logger:warning("manifest save failed: ~p", [Reason]),
            ok
    end.

-spec start_fuse_mount(binary(), term(), string()) ->
    {ok, pid()} | {error, term()}.
start_fuse_mount(ContainerId, Manifest, MountPath) ->
    try
        erlkoenig_fuse_mount_sup:start_mount(
            ContainerId, Manifest,
            #{mountpoint => MountPath})
    catch
        error:undef ->
            {error, fuse_mount_sup_not_available};
        _:Reason ->
            {error, Reason}
    end.

-doc "Cleanup FUSE mount when container stops or fails.".
-spec cleanup_fuse(#ct_data{}) -> ok.
cleanup_fuse(#ct_data{fuse_mount = undefined}) ->
    ok;
cleanup_fuse(#ct_data{id = ContainerId}) ->
    try
        _ = erlkoenig_fuse_mount_sup:stop_mount(ContainerId)
    catch
        _:_ -> ok
    end,
    ok.

%% --- Signature verification ---

-spec maybe_verify_signature(#ct_data{}) -> {ok, #ct_data{}} | {error, term()}.
maybe_verify_signature(Data) ->
    case erlkoenig_pki:mode() of
        off ->
            {ok, Data};
        Mode ->
            SigPath = resolve_sig_path(Data),
            case erlkoenig_sig:verify(Data#ct_data.binary_path, SigPath) of
                {ok, Meta} ->
                    erlkoenig_audit:log(#{
                        type => binary_verify,
                        subject => Data#ct_data.id,
                        result => ok,
                        details => maps:without([chain], Meta)
                    }),
                    case erlkoenig_pki:verify_chain(maps:get(chain, Meta)) of
                        ok ->
                            {ok, Data#ct_data{sig_verified = true, sig_meta = Meta}};
                        {error, ChainErr} when Mode =:= warn ->
                            logger:warning("[~s] chain verification failed: ~p (warn mode)",
                                          [Data#ct_data.id, ChainErr]),
                            erlkoenig_audit:log(#{
                                type => binary_verify,
                                subject => Data#ct_data.id,
                                result => {error, ChainErr},
                                details => #{mode => warn}
                            }),
                            {ok, Data};
                        {error, ChainErr} ->
                            erlkoenig_audit:log(#{
                                type => binary_reject,
                                subject => Data#ct_data.id,
                                result => {error, ChainErr},
                                details => #{binary => Data#ct_data.binary_path}
                            }),
                            {error, {chain_invalid, ChainErr}}
                    end;
                {error, Err} when Mode =:= warn ->
                    logger:warning("[~s] signature verification failed: ~p (warn mode)",
                                  [Data#ct_data.id, Err]),
                    erlkoenig_audit:log(#{
                        type => binary_verify,
                        subject => Data#ct_data.id,
                        result => {error, Err},
                        details => #{mode => warn}
                    }),
                    {ok, Data};
                {error, Err} ->
                    erlkoenig_audit:log(#{
                        type => binary_reject,
                        subject => Data#ct_data.id,
                        result => {error, Err},
                        details => #{binary => Data#ct_data.binary_path}
                    }),
                    {error, Err}
            end
    end.

-spec resolve_sig_path(#ct_data{}) -> binary().
resolve_sig_path(#ct_data{sig_path = undefined, binary_path = Bin}) ->
    <<Bin/binary, ".sig">>;
resolve_sig_path(#ct_data{sig_path = Path}) ->
    Path.
