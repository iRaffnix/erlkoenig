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

%%%-------------------------------------------------------------------
%% @doc erlkoenig_ct - Container lifecycle as gen_statem.
%%
%% One gen_statem per container. Manages the C port (erlkoenig_rt),
%% drives the SPAWN -> GO -> EXITED sequence, handles kill/stop.
%%
%% States:
%%   creating        -> Port opened, SPAWN sent
%%   namespace_ready -> Got container PID, ready for network setup
%%   starting        -> GO sent, waiting for ack
%%   running         -> Container executing
%%   stopping        -> SIGTERM sent, waiting for exit
%%   stopped         -> Container exited, cleanup done
%%   failed          -> Error occurred, stays alive for inspection
%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_ct).

-behaviour(gen_statem).

%% API
-export([start_link/2,
         go/1,
         stop_container/1,
         kill/2,
         get_info/1,
         attach/2,
         send_input/2,
         resize/3]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3]).
-export([creating/3, namespace_ready/3, starting/3,
         running/3, stopping/3, stopped/3, restarting/3, failed/3]).

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
    port          :: port() | undefined,
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
    extra_opts    = #{}        :: map()
}).

-define(SPAWN_TIMEOUT, application:get_env(erlkoenig_core, spawn_timeout, 30_000)).
-define(GO_TIMEOUT,    application:get_env(erlkoenig_core, go_timeout,    10_000)).
-define(STOP_TIMEOUT,  application:get_env(erlkoenig_core, stop_timeout,   5_000)).

%% =================================================================
%% API
%% =================================================================

-spec start_link(binary(), map()) -> gen_statem:start_ret().
start_link(BinaryPath, Opts) ->
    gen_statem:start_link(?MODULE, {BinaryPath, Opts}, []).

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

init({BinaryPath, Opts}) ->
    Id = make_id(),
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
        restart     = Restart,
        limits      = maps:get(limits, Opts, #{}),
        seccomp     = seccomp_profile_id(maps:get(seccomp, Opts, none)),
        caps_keep   = caps_to_mask(maps:get(caps, Opts, [])),
        output      = maps:get(output, Opts, undefined),
        name        = maps:get(name, Opts, undefined),
        files       = maps:get(files, Opts, #{}),
        pty         = maps:get(pty, Opts, false),
        extra_opts  = maps:without([args, env, uid, gid, ip, restart,
                                    limits, seccomp, caps, output, name,
                                    files, zone, pty], Opts)
    },
    {ok, creating, Data}.

terminate(_Reason, _State, #ct_data{port = Port}) when is_port(Port) ->
    safe_port_close(Port),
    ok;
terminate(_Reason, _State, _Data) ->
    ok.

%% =================================================================
%% creating - Open port, send SPAWN
%% =================================================================

creating(enter, _OldState, Data) ->
    BaseOpts = #{
        binary_path => Data#ct_data.binary_path,
        args        => Data#ct_data.args,
        env         => Data#ct_data.env,
        uid         => Data#ct_data.uid,
        gid         => Data#ct_data.gid,
        ip          => Data#ct_data.ip,
        limits      => Data#ct_data.limits,
        seccomp     => Data#ct_data.seccomp,
        name        => Data#ct_data.name
    },
    _SpawnOpts = maps:merge(BaseOpts, Data#ct_data.extra_opts),
    creating_do_spawn(Data);

creating(info, {Port, {data, Reply}}, #ct_data{port = Port, handshake = false} = Data) ->
    %% First message: protocol handshake reply
    case erlkoenig_proto:check_handshake_reply(Reply) of
        ok ->
            creating_send_spawn(Data),
            {keep_state, Data#ct_data{handshake = true}};
        {error, Reason} ->
            {next_state, failed,
             Data#ct_data{error_reason = Reason}}
    end;

creating(info, {Port, {data, Reply}}, #ct_data{port = Port, handshake = true} = Data) ->
    %% Second message: SPAWN reply
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_container_pid, #{child_pid := Pid, netns_path := Ns}} ->
            {next_state, namespace_ready,
             Data#ct_data{os_pid = Pid, netns_path = Ns}};
        {ok, reply_error, #{code := Code, message := Msg}} ->
            {next_state, failed,
             Data#ct_data{error_reason = {spawn_failed, Code, Msg}}};
        Other ->
            {next_state, failed,
             Data#ct_data{error_reason = {unexpected_reply, Other}}}
    end;

creating(info, {Port, {exit_status, Status}}, #ct_data{port = Port} = Data) ->
    {next_state, failed,
     Data#ct_data{port = undefined, error_reason = {port_died, Status}}};

creating(state_timeout, spawn_timeout, Data) ->
    {next_state, failed, Data#ct_data{error_reason = spawn_timeout}};

creating({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]}.

creating_do_spawn(Data) ->
    RtBin = rt_path(),
    Port = open_port({spawn_executable, RtBin},
                     [{packet, 4}, binary, exit_status, use_stdio]),
    %% Protocol handshake
    port_command(Port, erlkoenig_proto:encode_handshake()),
    {keep_state, Data#ct_data{port = Port},
     [{state_timeout, ?SPAWN_TIMEOUT, spawn_timeout}]}.

creating_send_spawn(Data) ->
    DiskMB = disk_limit_mb(Data#ct_data.limits),
    DnsIp  = zone_dns_ip(Data#ct_data.zone),
    Flags  = case Data#ct_data.pty of
                 true  -> erlkoenig_proto:spawn_flag_pty();
                 false -> 0
             end,
    Cmd = erlkoenig_proto:encode_cmd_spawn(
            Data#ct_data.binary_path,
            Data#ct_data.args,
            Data#ct_data.env,
            Data#ct_data.uid,
            Data#ct_data.gid,
            Data#ct_data.seccomp,
            DiskMB,
            Data#ct_data.caps_keep,
            DnsIp,
            Flags),
    port_command(Data#ct_data.port, Cmd).

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

namespace_ready(info, {Port, {data, Reply}}, #ct_data{port = Port} = Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_exited, ExitInfo} ->
            {next_state, stopped, Data#ct_data{exit_info = ExitInfo}};
        _Other ->
            keep_state_and_data
    end;

namespace_ready({call, From}, go, _Data) ->
    %% GO is now automatic after net setup. Just ack.
    {keep_state_and_data, [{reply, From, ok}]};

namespace_ready({call, _From}, stop_container, _Data) ->
    {keep_state_and_data, [postpone]};

namespace_ready({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(namespace_ready, Data)}]};

namespace_ready(info, {Port, {exit_status, Status}}, #ct_data{port = Port} = Data) ->
    {next_state, failed,
     Data#ct_data{port = undefined, error_reason = {port_died, Status}}}.

%% =================================================================
%% starting - GO sent, waiting for reply_ok
%% =================================================================

starting(enter, _OldState, _Data) ->
    {keep_state_and_data, [{state_timeout, ?GO_TIMEOUT, go_timeout}]};

starting(info, {Port, {data, Reply}}, #ct_data{port = Port} = Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_ok, _} ->
            Data2 = maybe_reply_go(Data),
            {next_state, running, Data2};
        {ok, reply_exited, ExitInfo} ->
            %% Child exited before we got reply_ok
            Data2 = maybe_reply_go(Data),
            {next_state, stopped,
             Data2#ct_data{exit_info = ExitInfo}};
        {ok, reply_error, #{code := Code, message := Msg}} ->
            Data2 = maybe_reply_go_error(Data, {go_failed, Code, Msg}),
            {next_state, failed,
             Data2#ct_data{error_reason = {go_failed, Code, Msg}}};
        {ok, reply_stdout, #{data := Chunk}} ->
            forward_output(stdout, Chunk, Data),
            keep_state_and_data;
        {ok, reply_stderr, #{data := Chunk}} ->
            forward_output(stderr, Chunk, Data),
            keep_state_and_data;
        Other ->
            {next_state, failed,
             Data#ct_data{error_reason = {unexpected_reply, Other}}}
    end;

starting(info, {Port, {exit_status, Status}}, #ct_data{port = Port} = Data) ->
    Data2 = maybe_reply_go_error(Data, {port_died, Status}),
    {next_state, failed,
     Data2#ct_data{port = undefined, error_reason = {port_died, Status}}};

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
    {keep_state, Data#ct_data{started_at = erlang:monotonic_time(millisecond)}};

running(info, {Port, {data, Reply}}, #ct_data{port = Port} = Data) ->
    case erlkoenig_proto:decode(Reply) of
        {ok, reply_exited, ExitInfo} ->
            {next_state, stopped, Data#ct_data{exit_info = ExitInfo}};
        {ok, reply_stdout, #{data := Chunk}} ->
            forward_output(stdout, Chunk, Data),
            keep_state_and_data;
        {ok, reply_stderr, #{data := Chunk}} ->
            forward_output(stderr, Chunk, Data),
            keep_state_and_data;
        _Other ->
            keep_state_and_data
    end;

running(info, {Port, {exit_status, _Status}}, #ct_data{port = Port} = Data) ->
    {next_state, stopped, Data#ct_data{port = undefined}};

running({call, From}, stop_container, Data) ->
    port_command(Data#ct_data.port, erlkoenig_proto:encode_cmd_kill(15)),
    {next_state, stopping, Data#ct_data{from = From, user_stopped = true}};

running({call, From}, {kill, Signal}, Data) ->
    port_command(Data#ct_data.port, erlkoenig_proto:encode_cmd_kill(Signal)),
    {next_state, stopping, Data,
     [{reply, From, ok}]};

running({call, From}, {attach, OutputPid}, Data) ->
    {keep_state, Data#ct_data{output = OutputPid}, [{reply, From, ok}]};

running({call, From}, {resize, Rows, Cols}, #ct_data{pty = true} = Data) ->
    port_command(Data#ct_data.port,
                 erlkoenig_proto:encode_cmd_resize(Rows, Cols)),
    {keep_state_and_data, [{reply, From, ok}]};

running({call, From}, {resize, _Rows, _Cols}, _Data) ->
    {keep_state_and_data, [{reply, From, {error, not_pty}}]};

running({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(running, Data)}]};

running(cast, {send_input, InputData}, #ct_data{port = Port}) ->
    port_command(Port, erlkoenig_proto:encode_cmd_stdin(InputData)),
    keep_state_and_data.

%% =================================================================
%% stopping - SIGTERM sent, waiting for exit
%% =================================================================

stopping(enter, _OldState, _Data) ->
    {keep_state_and_data, [{state_timeout, ?STOP_TIMEOUT, force_kill}]};

stopping(info, {Port, {data, Reply}}, #ct_data{port = Port} = Data) ->
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
    end;

stopping(info, {Port, {exit_status, _Status}}, #ct_data{port = Port} = Data) ->
    Data2 = maybe_reply_stop(Data, ok),
    {next_state, stopped, Data2#ct_data{port = undefined}};

stopping(state_timeout, force_kill, #ct_data{port = Port}) when is_port(Port) ->
    port_command(Port, erlkoenig_proto:encode_cmd_kill(9)),
    {keep_state_and_data, [{state_timeout, ?STOP_TIMEOUT, give_up}]};

stopping(state_timeout, give_up, Data) ->
    Data2 = maybe_reply_stop(Data, {error, kill_timeout}),
    {next_state, failed, Data2#ct_data{error_reason = kill_timeout}};

stopping({call, _From}, _, _Data) ->
    {keep_state_and_data, [postpone]}.

%% =================================================================
%% stopped - Container exited, check restart policy
%% =================================================================

stopped(enter, _OldState, #ct_data{port = Port} = Data) when is_port(Port) ->
    pg:leave(erlkoenig_pg, erlkoenig_cts, self()),
    firewall_remove(Data#ct_data.id),
    safe_port_close(Port),
    dns_unregister(Data),
    notify_stopped(Data),
    self() ! check_restart,
    {keep_state, Data#ct_data{port = undefined}};
stopped(enter, _OldState, Data) ->
    pg:leave(erlkoenig_pg, erlkoenig_cts, self()),
    firewall_remove(Data#ct_data.id),
    dns_unregister(Data),
    notify_stopped(Data),
    self() ! check_restart,
    keep_state_and_data;

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
        handshake    = false
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

failed(enter, _OldState, #ct_data{port = Port} = Data) ->
    pg:leave(erlkoenig_pg, erlkoenig_cts, self()),
    firewall_remove(Data#ct_data.id),
    safe_port_close(Port),
    dns_unregister(Data),
    erlkoenig_events:notify({container_failed, Data#ct_data.id,
                           Data#ct_data.error_reason}),
    logger:error("container ~s failed: ~p",
                 [Data#ct_data.id, Data#ct_data.error_reason]),
    self() ! check_restart,
    {keep_state, Data#ct_data{port = undefined}};

failed(info, check_restart, Data) ->
    handle_check_restart(Data);

failed({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, build_info(failed, Data)}]};

failed({call, From}, stop_container, Data) ->
    {keep_state, Data#ct_data{user_stopped = true}, [{reply, From, ok}]};

failed({call, From}, _, _Data) ->
    {keep_state_and_data, [{reply, From, {error, failed}}]}.

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
do_container_setup(#ct_data{id = Id, port = Port, os_pid = OsPid,
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
            setup_device_filter(Port, Id);
        false ->
            ok
    end,
    %% Step 2: network + files + GO.
    %% Note: uid_map/gid_map is written by the C runtime (erlkoenig_ns.c)
    %% immediately after clone, before replying with container_pid.
    %% By the time we get here, the child already has capabilities.
    do_container_net_setup(Data).

-spec do_container_net_setup(#ct_data{}) ->
    {next_state, atom(), #ct_data{}}.
do_container_net_setup(#ct_data{port = Port, id = Id, ip = Ip,
                                os_pid = OsPid, zone = Zone} = Data) ->
    NetResult = case Ip of
        undefined -> erlkoenig_net:setup_container_net(Port, Id, OsPid, Zone);
        _         -> erlkoenig_net:setup_container_net(Port, Id, OsPid, Ip, Zone)
    end,
    case NetResult of
        {ok, NetInfo} ->
            firewall_add(Id, NetInfo, Data#ct_data.extra_opts),
            write_container_files(Port, Data#ct_data.files),
            port_command(Port, erlkoenig_proto:encode_cmd_go()),
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

-spec validate_restart(term()) -> erlkoenig_core:restart_policy().
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

-spec write_container_files(port(), #{binary() => binary()}) -> ok.
write_container_files(_Port, Files) when map_size(Files) =:= 0 -> ok;
write_container_files(Port, Files) ->
    maps:foreach(fun(Path, Data) ->
        Cmd = erlkoenig_proto:encode_cmd_write_file(Path, 8#644, Data),
        port_command(Port, Cmd)
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

%% -- Port cleanup -------------------------------------------------

-spec safe_port_close(port() | undefined) -> ok.
safe_port_close(Port) when is_port(Port) ->
    try port_close(Port)
    catch error:badarg -> ok
    end;
safe_port_close(_) ->
    ok.

%% -- Firewall (direct nft integration) ----------------------------

-spec firewall_add(binary(), map(), map()) -> ok.
firewall_add(ContainerId, #{ip := Ip, host_veth := Veth} = _NetInfo, ExtraOpts) ->
    Ports = maps:get(ports, ExtraOpts, []),
    FwTerm = maps:get(firewall, ExtraOpts, #{}),
    case erlkoenig_firewall_nft:add_container(ContainerId, Ip, Veth, Ports, FwTerm) of
        ok -> ok;
        {error, Reason} ->
            logger:warning("firewall: failed to create chain for ~s: ~p",
                           [ContainerId, Reason])
    end,
    ok;
firewall_add(_ContainerId, _NetInfo, _ExtraOpts) ->
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

%% @doc Get the DNS IP for a zone as a 32-bit network-order integer.
%% The DNS server runs on the zone's gateway IP.
-spec zone_dns_ip(atom()) -> non_neg_integer().
zone_dns_ip(default) ->
    ip4_to_u32(application:get_env(erlkoenig_core, gateway, {10, 0, 0, 1}));
zone_dns_ip(ZoneName) ->
    #{gateway := Gw} = erlkoenig_zone:zone_config(ZoneName),
    ip4_to_u32(Gw).

-spec ip4_to_u32(inet:ip4_address()) -> non_neg_integer().
ip4_to_u32({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

-spec seccomp_profile_id(erlkoenig_core:seccomp_profile() | non_neg_integer()) -> non_neg_integer().
seccomp_profile_id(none)    -> 0;
seccomp_profile_id(default) -> 1;
seccomp_profile_id(strict)  -> 2;
seccomp_profile_id(network) -> 3;
seccomp_profile_id(N) when is_integer(N), N >= 0, N =< 255 -> N;
seccomp_profile_id(Other) -> error({invalid_seccomp_profile, Other}).

-spec seccomp_profile_name(non_neg_integer()) -> erlkoenig_core:seccomp_profile() | non_neg_integer().
seccomp_profile_name(0) -> none;
seccomp_profile_name(1) -> default;
seccomp_profile_name(2) -> strict;
seccomp_profile_name(3) -> network;
seccomp_profile_name(N) -> N.

%% =================================================================
%% Capabilities: atom list <-> 64-bit bitmask
%% =================================================================

-spec cap_bit(erlkoenig_core:capability()) -> 0..40.
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

-spec caps_to_mask([erlkoenig_core:capability()]) -> non_neg_integer().
caps_to_mask([]) -> 0;
caps_to_mask(Caps) when is_list(Caps) ->
    lists:foldl(fun(Cap, Acc) ->
        Acc bor (1 bsl cap_bit(Cap))
    end, 0, Caps).

-spec mask_to_caps(non_neg_integer()) -> [erlkoenig_core:capability()].
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
    case erlkoenig_cgroup:create(Id) of
        ok ->
            case erlkoenig_cgroup:attach(Id, OsPid) of
                ok when map_size(Limits) =:= 0 ->
                    ok;
                ok ->
                    erlkoenig_cgroup:set_limits(Id, Limits);
                Error ->
                    _ = erlkoenig_cgroup:destroy(Id),
                    Error
            end;
        Error ->
            Error
    end.

-spec setup_device_filter(port(), binary()) -> ok.
setup_device_filter(Port, Id) ->
    case erlkoenig_cgroup:path(Id) of
        {ok, CgroupPath} ->
            CgroupBin = list_to_binary(CgroupPath),
            Cmd = erlkoenig_proto:encode_cmd_device_filter(CgroupBin),
            port_command(Port, Cmd),
            receive
                {Port, {data, Reply}} ->
                    case erlkoenig_proto:decode(Reply) of
                        {ok, reply_ok, _} ->
                            logger:debug("container ~s: device filter attached",
                                         [Id]);
                        {ok, reply_error, #{code := Code, message := Msg}} ->
                            logger:warning("container ~s: device filter failed: "
                                           "~p ~s (continuing without)",
                                           [Id, Code, Msg])
                    end
            after 5000 ->
                logger:warning("container ~s: device filter timeout", [Id])
            end;
        {error, _} ->
            ok
    end,
    ok.

-spec make_id() -> erlkoenig_core:container_id().
make_id() ->
    <<A:32, B:16, C:16, D:16, E:48>> = crypto:strong_rand_bytes(16),
    list_to_binary(io_lib:format(
      "~8.16.0b-~4.16.0b-~4.16.0b-~4.16.0b-~12.16.0b",
      [A, B, C band 16#0fff bor 16#4000,
       D band 16#3fff bor 16#8000, E])).

-spec rt_path() -> string().
rt_path() ->
    case application:get_env(erlkoenig_core, rt_path, auto) of
        auto -> find_rt();
        Path -> Path
    end.

-spec find_rt() -> string().
find_rt() ->
    Candidates = [
        fun() -> os:find_executable("erlkoenig_rt") end,
        fun() -> check_path("/usr/lib/erlkoenig/erlkoenig_rt") end,
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
    try code:priv_dir(erlkoenig_core) of
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

-spec build_info(atom(), #ct_data{}) -> erlkoenig_core:container_info().
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
        ports         => maps:get(ports, Data#ct_data.extra_opts, [])
    },
    maybe_add_optional_fields(State, Data, Info).

-spec maybe_add_optional_fields(atom(), #ct_data{}, map()) -> erlkoenig_core:container_info().
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
