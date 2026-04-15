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

-module(erlkoenig).
-moduledoc """
Public API for container management.

Usage from the Erlang shell:
  {ok, Pid} = erlkoenig:spawn(Path).
  erlkoenig:list().
  erlkoenig:inspect(Pid).
  erlkoenig:stop(Pid).
""".

-export([spawn/1, spawn/2,
         stop/1,
         kill/2,
         list/0,
         inspect/1,
         stats/1,
         attach/1, attach/2,
         health_check/2,
         remove_health_check/1,
         health_status/0,
         subscribe/2,
         unsubscribe/2,
         find_by_id/1]).

-export_type([container_id/0, container_pid/0, spawn_opts/0,
              container_info/0, net_info/0, exit_info/0,
              restart_policy/0, limit_opts/0, seccomp_profile/0,
              capability/0, ip4/0]).

%%% --------------------------------------------------------------------
%%% Types
%%% --------------------------------------------------------------------

-type container_id()  :: binary().
-type container_pid() :: pid().
-type ip4()           :: inet:ip4_address().

-type seccomp_profile() :: none | default | strict | network.

-type capability() :: chown | dac_override | dac_read_search | fowner
                    | fsetid | kill | setgid | setuid | setpcap
                    | linux_immutable | net_bind_service | net_broadcast
                    | net_admin | net_raw | ipc_lock | ipc_owner
                    | sys_module | sys_rawio | sys_chroot | sys_ptrace
                    | sys_pacct | sys_admin | sys_boot | sys_nice
                    | sys_resource | sys_time | sys_tty_config | mknod
                    | lease | audit_write | audit_control | setfcap
                    | mac_override | mac_admin | syslog | wake_alarm
                    | block_suspend | audit_read | perfmon | bpf
                    | checkpoint_restore.

-type restart_policy() :: no_restart
                        | always
                        | on_failure
                        | {always, pos_integer()}
                        | {on_failure, pos_integer()}
                        %% OTP-style aliases (preferred from the DSL):
                        %% permanent = always, transient = on_failure,
                        %% temporary = no_restart.
                        | permanent
                        | transient
                        | temporary.

-type limit_opts() :: #{memory => pos_integer(),
                        cpu => 1..100,
                        pids => pos_integer(),
                        disk => pos_integer()}.

-type spawn_opts() :: #{args => [binary()],
                        env => [{binary(), binary()}],
                        uid => non_neg_integer(),
                        gid => non_neg_integer(),
                        ip => ip4(),
                        zone => atom(),
                        name => binary(),
                        restart => restart_policy(),
                        limits => limit_opts(),
                        seccomp => seccomp_profile(),
                        caps => [capability()],
                        output => pid(),
                        files => #{binary() => binary()},
                        rootfs_size_mb => pos_integer()}.

-type net_info() :: #{ip := ip4(),
                      gateway := ip4(),
                      netmask := non_neg_integer(),
                      iface := binary(),
                      %% Backward compat: set to `undefined` in IPVLAN mode
                      host_veth => binary() | undefined,
                      container_veth => binary() | undefined}.

-type exit_info() :: #{exit_code := integer(),
                       term_signal := non_neg_integer()}.

-type container_info() :: #{id := container_id(),
                            state := atom(),
                            binary := binary(),
                            os_pid := non_neg_integer() | undefined,
                            netns_path := binary() | undefined,
                            restart := restart_policy(),
                            restart_count := non_neg_integer(),
                            limits := limit_opts(),
                            seccomp := seccomp_profile(),
                            caps := [capability()],
                            name := binary() | undefined,
                            zone := binary() | undefined,
                            args := [binary()],
                            ports := [{inet:port_number(), inet:port_number()}],
                            volumes := [map()],
                            net_info => net_info(),
                            exit_info => exit_info(),
                            error => term(),
                            stats => map()}.

%%% ====================================================================
%%% API
%%% ====================================================================

-doc "Spawn a container running the given static binary.".
-spec spawn(binary()) -> {ok, container_pid()} | {error, term()}.
spawn(BinaryPath) ->
    ?MODULE:spawn(BinaryPath, #{}).

-doc "Spawn a container with options.".
-spec spawn(binary(), spawn_opts()) -> {ok, container_pid()} | {error, term()}.
spawn(BinaryPath, Opts) ->
    erlkoenig_sup:start_container(BinaryPath, Opts).

-doc "Stop a container (SIGTERM, then SIGKILL after timeout).".
-spec stop(container_pid()) -> ok | {error, term()}.
stop(Pid) ->
    erlkoenig_ct:stop_container(Pid).

-doc "Send a signal to the container.".
-spec kill(container_pid(), non_neg_integer()) -> ok | {error, term()}.
kill(Pid, Signal) ->
    erlkoenig_ct:kill(Pid, Signal).

-doc "List all running containers.".
-spec list() -> [container_info()].
list() ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch error:_ -> []
           end,
    [erlkoenig_ct:get_info(Pid) || Pid <- Pids].

-doc "Get detailed info about a container.".
-spec inspect(container_pid()) -> container_info() | {error, not_found}.
inspect(Pid) ->
    try erlkoenig_ct:get_info(Pid)
    catch exit:{noproc, _} -> {error, not_found}
    end.

-doc "Find a container PID by its ID (binary string).".
-spec find_by_id(binary()) -> {ok, pid()} | {error, not_found}.
find_by_id(Id) ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch error:_ -> []
           end,
    find_pid_by_id(Pids, Id).

find_pid_by_id([], _Id) -> {error, not_found};
find_pid_by_id([Pid | Rest], Id) ->
    try
        Info = erlkoenig_ct:get_info(Pid),
        case maps:get(id, Info, undefined) of
            Id -> {ok, Pid};
            _  -> find_pid_by_id(Rest, Id)
        end
    catch
        _:_ -> find_pid_by_id(Rest, Id)
    end.

-doc "Get live resource stats for a container (cgroup v2). Returns #{memory_bytes, memory_peak, cpu_usec, pids_current}.".
-spec stats(container_pid()) -> {ok, map()} | {error, term()}.
stats(Pid) ->
    try erlkoenig_ct:get_info(Pid) of
        #{id := Id, state := running} ->
            erlkoenig_cgroup:read_stats(Id);
        #{state := State} ->
            {error, {not_running, State}}
    catch exit:{noproc, _} -> {error, not_found}
    end.

-doc """
Attach to a container's stdout/stderr.

Starts forwarding output to the calling process.
Messages: {container_stdout, Pid, Id, Chunk}
          {container_stderr, Pid, Id, Chunk}

Returns {ok, Ref} where Ref can be used with detach/1.
""".
-spec attach(container_pid()) -> ok | {error, term()}.
attach(Pid) ->
    attach(Pid, self()).

-spec attach(container_pid(), pid()) -> ok | {error, term()}.
attach(ContainerPid, OutputPid) ->
    erlkoenig_ct:attach(ContainerPid, OutputPid).

-doc """
Add a health check for a container.

Opts:
  type     => tcp             (only tcp for now)
  port     => 8080            (required)
  interval => 5000            (ms between checks, default 5s)
  timeout  => 2000            (connect timeout, default 2s)
  retries  => 3               (failures before restart, default 3)

The container must have a restart policy set, otherwise the health
check will stop it but it won't come back.
""".
-spec health_check(container_pid(), map()) -> ok | {error, term()}.
health_check(Pid, Opts) ->
    erlkoenig_health:add(Pid, Opts).

-doc "Remove a health check for a container.".
-spec remove_health_check(container_pid()) -> ok.
remove_health_check(Pid) ->
    erlkoenig_health:remove(Pid).

-doc "Get status of all health checks.".
-spec health_status() -> [map()].
health_status() ->
    erlkoenig_health:status().

-doc """
Subscribe an event handler to container lifecycle events.

Events:
  {container_started,    Id, Pid}       - entered running
  {container_stopped,    Id, ExitInfo}  - exited
  {container_failed,     Id, Reason}    - error state
  {container_restarting, Id, Attempt}   - restart scheduled
  {container_oom,        Id}            - OOM-Kill detected
""".
-spec subscribe(module(), term()) -> ok | {error, term()}.
subscribe(Handler, Args) ->
    erlkoenig_events:subscribe(Handler, Args).

-doc "Unsubscribe an event handler.".
-spec unsubscribe(module(), term()) -> ok | {error, term()}.
unsubscribe(Handler, Args) ->
    erlkoenig_events:unsubscribe(Handler, Args).
