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

-module(erlkoenig_cgroup).
-moduledoc """
cgroups v2 resource management with protected BEAM topology.

Manages a three-level cgroup hierarchy for erlkoenig:

    <base>/                     — top-level delegated/created cgroup
    <base>/beam/                — BEAM VM processes (memory.min guarantee)
    <base>/containers/          — ceiling cgroup for all containers
    <base>/containers/<id>/     — per-container cgroup

The base cgroup path is auto-detected:
  - Under systemd with Delegate=yes: uses the delegated cgroup
    (e.g. /sys/fs/cgroup/system.slice/erlkoenig.service/erlkoenig/)
  - Running as root: /sys/fs/cgroup/erlkoenig/

The beam/ subtree gets a kernel-guaranteed memory reserve (memory.min),
a leak-protection ceiling (memory.max), elevated CPU priority (cpu.weight),
and a PID limit. The containers/ subtree gets an aggregate ceiling for
memory and PIDs so that container workloads cannot starve the BEAM.

Supported per-container limits (all optional):
  memory  - Max memory in bytes (written to memory.max)
  cpu     - CPU percentage of one core, 1-100 (written to cpu.max)
  pids    - Max number of processes (written to pids.max)

The gen_server creates the full topology on init and enables the required
controllers. On terminate, it removes containers/, beam/, and base
(best-effort, log and ignore errors).

All operations are pure file I/O on cgroupfs — no os:cmd.
""".

-behaviour(gen_server).

%% API
-export([start_link/0,
         create/1,
         attach/2,
         set_limits/2,
         destroy/1,
         read_stats/1,
         read_containers_stats/0,
         was_oom_killed/1,
         path/1]).

%% Configuration (exported for testing)
-export([beam_config/0,
         containers_config/0,
         validate_beam_config/1,
         validate_containers_config/1,
         compute_containers_memory_max/3,
         parse_memtotal/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(CGROUP_ROOT, "/sys/fs/cgroup").

%% CPU period in microseconds (fixed at 1 second).
-define(CPU_PERIOD, 1_000_000).

%% Minimum containers memory — below this nothing useful runs.
-define(MIN_CONTAINERS_MEMORY, 134_217_728). %% 128 MB

-record(state, {
    base_path       :: string(),   %% e.g. "/sys/fs/cgroup/system.slice/erlkoenig.service/erlkoenig"
    beam_path       :: string(),   %% base_path ++ "/beam"
    containers_path :: string()    %% base_path ++ "/containers"
}).

%% =================================================================
%% API
%% =================================================================

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc "Create a cgroup for a container.".
-spec create(binary()) -> ok | {error, term()}.
create(ContainerId) ->
    gen_server:call(?MODULE, {create, ContainerId}).

-doc "Move a process into a container's cgroup.".
-spec attach(binary(), non_neg_integer()) -> ok | {error, term()}.
attach(ContainerId, OsPid) ->
    gen_server:call(?MODULE, {attach, ContainerId, OsPid}).

-doc """
Set resource limits for a container.

Limits is a map with optional keys:
  memory => Bytes      (e.g. 64_000_000 for 64 MB)
  cpu    => Percent     (e.g. 50 for 50% of one core)
  pids   => MaxPids    (e.g. 64)
""".
-spec set_limits(binary(), map()) -> ok | {error, term()}.
set_limits(ContainerId, Limits) ->
    gen_server:call(?MODULE, {set_limits, ContainerId, Limits}).

-doc """
Remove a container's cgroup.

The cgroup must be empty (no processes). Deleting a cgroup with
processes still in it will fail with EBUSY.
""".
-spec destroy(binary()) -> ok | {error, term()}.
destroy(ContainerId) ->
    gen_server:call(?MODULE, {destroy, ContainerId}).

-doc "Read live resource stats from a container's cgroup.".
-spec read_stats(binary()) -> {ok, map()} | {error, term()}.
read_stats(ContainerId) ->
    gen_server:call(?MODULE, {read_stats, ContainerId}).

-doc "Read stats from the containers ceiling cgroup (aggregate).".
-spec read_containers_stats() -> {ok, map()} | {error, term()}.
read_containers_stats() ->
    gen_server:call(?MODULE, read_containers_stats).

-doc "Check if a container was OOM-killed by reading memory.events.".
-spec was_oom_killed(binary()) -> boolean().
was_oom_killed(ContainerId) ->
    gen_server:call(?MODULE, {was_oom_killed, ContainerId}).

-doc "Get the absolute cgroup directory path for a container.".
-spec path(binary()) -> {ok, string()} | {error, term()}.
path(ContainerId) ->
    gen_server:call(?MODULE, {path, ContainerId}).

%% =================================================================
%% gen_server callbacks
%% =================================================================

init([]) ->
    process_flag(trap_exit, true),
    proc_lib:set_label(erlkoenig_cgroup),
    BasePath = detect_base_path(),
    logger:info("erlkoenig_cgroup: detected base path ~s", [BasePath]),
    case setup_protected_topology(BasePath) of
        {ok, BeamPath, ContainersPath} ->
            logger:info("erlkoenig_cgroup: setup complete at ~s", [BasePath]),
            {ok, #state{base_path = BasePath,
                        beam_path = BeamPath,
                        containers_path = ContainersPath}};
        {error, Reason} ->
            logger:error("erlkoenig_cgroup: setup failed at ~s: ~p", [BasePath, Reason]),
            {stop, {cgroup_setup_failed, Reason}}
    end.

handle_call({create, ContainerId}, _From, #state{containers_path = CPath} = State) ->
    Path = container_path(CPath, ContainerId),
    Result = case file:make_dir(Path) of
        ok              -> ok;
        {error, eexist} -> ok;
        Error           -> Error
    end,
    {reply, Result, State};

handle_call({attach, ContainerId, OsPid}, _From, #state{containers_path = CPath} = State) ->
    Path = filename:join(container_path(CPath, ContainerId), "cgroup.procs"),
    Result = file:write_file(Path, integer_to_list(OsPid)),
    {reply, Result, State};

handle_call({set_limits, ContainerId, Limits}, _From, #state{containers_path = CPath} = State) ->
    Path = container_path(CPath, ContainerId),
    Results = lists:flatten([
        apply_limit(Path, memory, maps:get(memory, Limits, undefined)),
        apply_limit(Path, cpu,    maps:get(cpu, Limits, undefined)),
        apply_limit(Path, pids,   maps:get(pids, Limits, undefined))
    ]),
    Result = case [E || {error, _} = E <- Results] of
        []        -> ok;
        [First|_] -> First
    end,
    {reply, Result, State};

handle_call({destroy, ContainerId}, _From, #state{containers_path = CPath} = State) ->
    Path = container_path(CPath, ContainerId),
    Result = case file:del_dir(Path) of
        ok              -> ok;
        {error, enoent} -> ok;
        Error           -> Error
    end,
    {reply, Result, State};

handle_call({read_stats, ContainerId}, _From, #state{containers_path = CPath} = State) ->
    Path = container_path(CPath, ContainerId),
    Result = case filelib:is_dir(Path) of
        false ->
            {error, enoent};
        true ->
            Stats = lists:foldl(fun(F, Acc) -> F(Path, Acc) end, #{}, [
                fun read_memory_current/2,
                fun read_memory_peak/2,
                fun read_cpu_stat/2,
                fun read_pids_current/2
            ]),
            {ok, Stats}
    end,
    {reply, Result, State};

handle_call(read_containers_stats, _From, #state{containers_path = CPath} = State) ->
    Result = case filelib:is_dir(CPath) of
        false ->
            {error, enoent};
        true ->
            Stats = lists:foldl(fun(F, Acc) -> F(CPath, Acc) end, #{}, [
                fun read_memory_current/2,
                fun read_memory_peak/2,
                fun read_cpu_stat/2,
                fun read_pids_current/2
            ]),
            {ok, Stats}
    end,
    {reply, Result, State};

handle_call({was_oom_killed, ContainerId}, _From, #state{containers_path = CPath} = State) ->
    Path = container_path(CPath, ContainerId),
    File = filename:join(Path, "memory.events"),
    Result = case file:read_file(File) of
        {ok, Bin} -> parse_oom_kill(Bin);
        _         -> false
    end,
    {reply, Result, State};

handle_call({path, ContainerId}, _From, #state{containers_path = CPath} = State) ->
    Path = container_path(CPath, ContainerId),
    Result = case filelib:is_dir(Path) of
        true  -> {ok, Path};
        false -> {error, not_found}
    end,
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, #state{base_path = BasePath, beam_path = BeamPath,
                          containers_path = ContainersPath}) ->
    %% Best-effort removal of cgroup hierarchy.
    %% Clean up containers/, then beam/, then base.
    %% del_dir on non-empty cgroups will fail — log and ignore.
    case file:del_dir(ContainersPath) of
        ok -> ok;
        {error, CErr} ->
            logger:warning("erlkoenig_cgroup: del_dir ~s failed: ~p",
                           [ContainersPath, CErr])
    end,
    case file:del_dir(BeamPath) of
        ok -> ok;
        {error, BErr} ->
            logger:warning("erlkoenig_cgroup: del_dir ~s failed: ~p",
                           [BeamPath, BErr])
    end,
    case file:del_dir(BasePath) of
        ok -> ok;
        {error, BaseErr} ->
            logger:warning("erlkoenig_cgroup: del_dir ~s failed: ~p",
                           [BasePath, BaseErr])
    end,
    ok.

%% =================================================================
%% Configuration (A2)
%% =================================================================

-doc "Read beam cgroup configuration from app env with defaults.".
-spec beam_config() -> map().
beam_config() ->
    Cfg = application:get_env(erlkoenig, resource_protection, #{}),
    Beam = #{memory_min => maps:get(beam_memory_min, Cfg, 268_435_456),
             memory_max => maps:get(beam_memory_max, Cfg, 536_870_912),
             cpu_weight => maps:get(beam_cpu_weight, Cfg, 200),
             pids_max   => maps:get(beam_pids_max, Cfg, 8192)},
    ok = validate_beam_config(Beam),
    Beam.

-doc "Read containers ceiling configuration from app env, resolving 'auto'.".
-spec containers_config() -> map().
containers_config() ->
    Cfg = application:get_env(erlkoenig, resource_protection, #{}),
    MemMax = case maps:get(containers_memory_max, Cfg, auto) of
        auto ->
            {ok, MemTotal} = read_memtotal(),
            HostReserve = maps:get(host_reserve, Cfg, 1_073_741_824),
            BeamMax = maps:get(beam_memory_max, Cfg, 536_870_912),
            compute_containers_memory_max(MemTotal, HostReserve, BeamMax);
        Explicit when is_integer(Explicit) ->
            Explicit
    end,
    PidsMax = maps:get(containers_pids_max, Cfg, 24576),
    Containers = #{memory_max => MemMax, pids_max => PidsMax},
    ok = validate_containers_config(Containers),
    Containers.

-doc "Validate beam cgroup configuration. Crashes on invalid config.".
-spec validate_beam_config(map()) -> ok | no_return().
validate_beam_config(#{memory_min := Min, memory_max := Max,
                       cpu_weight := Weight, pids_max := Pids}) ->
    Min > 0 orelse error({invalid_config, beam_memory_min_must_be_positive, Min}),
    Max >= Min orelse error({invalid_config, beam_memory_max_lt_min, #{max => Max, min => Min}}),
    Weight > 0 orelse error({invalid_config, beam_cpu_weight_must_be_positive, Weight}),
    Pids > 0 orelse error({invalid_config, beam_pids_max_must_be_positive, Pids}),
    ok.

-doc "Validate containers ceiling configuration. Crashes on invalid config.".
-spec validate_containers_config(map()) -> ok | no_return().
validate_containers_config(#{memory_max := MemMax, pids_max := Pids}) ->
    MemMax >= ?MIN_CONTAINERS_MEMORY orelse
        error({invalid_config, containers_memory_max_too_low,
               #{value => MemMax, minimum => ?MIN_CONTAINERS_MEMORY}}),
    Pids > 0 orelse error({invalid_config, containers_pids_max_must_be_positive, Pids}),
    ok.

-doc "Pure function: compute containers memory ceiling from system parameters.".
-spec compute_containers_memory_max(pos_integer(), non_neg_integer(), non_neg_integer()) ->
    pos_integer().
compute_containers_memory_max(MemTotal, HostReserve, BeamMax) ->
    MemTotal - HostReserve - BeamMax.

-doc "Read total system memory from /proc/meminfo.".
-spec read_memtotal() -> {ok, pos_integer()} | {error, term()}.
read_memtotal() ->
    case file:read_file("/proc/meminfo") of
        {ok, Bin} ->
            case parse_memtotal(Bin) of
                {ok, _} = Ok -> Ok;
                error -> {error, memtotal_parse_failed}
            end;
        {error, Reason} ->
            {error, {meminfo_unavailable, Reason}}
    end.

-doc "Parse MemTotal from /proc/meminfo content.".
-spec parse_memtotal(binary()) -> {ok, pos_integer()} | error.
parse_memtotal(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    parse_memtotal_lines(Lines).

-spec parse_memtotal_lines([binary()]) -> {ok, pos_integer()} | error.
parse_memtotal_lines([]) -> error;
parse_memtotal_lines([Line | Rest]) ->
    case binary:split(Line, <<" ">>, [global, trim_all]) of
        [<<"MemTotal:">>, KBStr, <<"kB">>] ->
            try {ok, binary_to_integer(KBStr) * 1024}
            catch _:_ -> error
            end;
        _ ->
            parse_memtotal_lines(Rest)
    end.

-doc "Log applied protection configuration at notice level.".
-spec log_protection_config(map(), map(), string()) -> ok.
log_protection_config(BeamCfg, ContainersCfg, Source) ->
    logger:notice("erlkoenig_cgroup: beam protection: "
                  "memory.min=~s memory.max=~s cpu.weight=~b pids.max=~b [~s]",
                  [format_bytes(maps:get(memory_min, BeamCfg)),
                   format_bytes(maps:get(memory_max, BeamCfg)),
                   maps:get(cpu_weight, BeamCfg),
                   maps:get(pids_max, BeamCfg),
                   Source]),
    logger:notice("erlkoenig_cgroup: containers ceiling: "
                  "memory.max=~s pids.max=~b [~s]",
                  [format_bytes(maps:get(memory_max, ContainersCfg)),
                   maps:get(pids_max, ContainersCfg),
                   Source]),
    ok.

%% =================================================================
%% Internal
%% =================================================================

-spec container_path(string(), binary()) -> string().
container_path(ContainersPath, ContainerId) when is_binary(ContainerId) ->
    filename:join(ContainersPath, binary_to_list(ContainerId)).

-doc """
Auto-detect the cgroup base path.

Under systemd with Delegate=yes, the process runs in a delegated
cgroup like /sys/fs/cgroup/system.slice/erlkoenig.service/.
We use that directly as the base path for container cgroups.

When running as root (or in the root cgroup), we create
/sys/fs/cgroup/erlkoenig/ as a dedicated cgroup.
""".
-spec detect_base_path() -> string().
detect_base_path() ->
    case file:read_file("/proc/self/cgroup") of
        {ok, Bin} ->
            case parse_cgroup_v2_path(Bin) of
                {ok, "/"} ->
                    %% Root cgroup — use traditional path
                    filename:join(?CGROUP_ROOT, "erlkoenig");
                {ok, CgroupPath} ->
                    %% Delegated cgroup — use it directly.
                    %% CgroupPath is absolute (e.g. "/system.slice/erlkoenig.service")
                    %% so we concatenate rather than join (which would drop the prefix).
                    %% Strip trailing "/init" or "/beam" — those are child cgroups
                    %% from previous or current topology. The base path is the parent.
                    BaseCgroup = strip_child_cgroup(CgroupPath),
                    ?CGROUP_ROOT ++ BaseCgroup;
                error ->
                    filename:join(?CGROUP_ROOT, "erlkoenig")
            end;
        _ ->
            filename:join(?CGROUP_ROOT, "erlkoenig")
    end.

%% Strip trailing /init or /beam from a cgroup path — those are child
%% cgroups from the old or new topology.
-spec strip_child_cgroup(string()) -> string().
strip_child_cgroup(Path) ->
    case lists:suffix("/init", Path) of
        true  -> lists:sublist(Path, length(Path) - 5);
        false ->
            case lists:suffix("/beam", Path) of
                true  -> lists:sublist(Path, length(Path) - 5);
                false -> Path
            end
    end.

%% Parse the cgroup v2 path from /proc/self/cgroup.
%% Format: "0::/path\n" (cgroup v2 uses hierarchy-ID 0)
-spec parse_cgroup_v2_path(binary()) -> {ok, string()} | error.
parse_cgroup_v2_path(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    parse_cgroup_v2_lines(Lines).

-spec parse_cgroup_v2_lines([binary()]) -> {ok, string()} | error.
parse_cgroup_v2_lines([]) -> error;
parse_cgroup_v2_lines([<<"0::", Path/binary>> | _]) ->
    {ok, binary_to_list(string:trim(Path))};
parse_cgroup_v2_lines([_ | Rest]) ->
    parse_cgroup_v2_lines(Rest).

-spec setup_protected_topology(string()) -> {ok, string(), string()} | {error, term()}.
setup_protected_topology(BasePath) ->
    BeamPath = filename:join(BasePath, "beam"),
    ContainersPath = filename:join(BasePath, "containers"),
    maybe
        %% 1. Ensure base cgroup directory exists
        ok ?= ensure_dir(BasePath),
        %% 2. Create beam/ and containers/ subtrees
        ok ?= ensure_dir(BeamPath),
        ok ?= ensure_dir(ContainersPath),
        %% 3. Move BEAM processes to beam/.
        %%    Processes may be in BasePath/cgroup.procs (root cgroup) or
        %%    in BasePath/init/cgroup.procs (systemd DelegateSubgroup=init).
        %%    Move from both sources — one will be a no-op.
        InitPath = filename:join(BasePath, "init"),
        ok ?= move_processes_to(InitPath, BeamPath),
        ok ?= move_processes_to(BasePath, BeamPath),
        %% 3b. Verify: neither BasePath nor init/ has processes left
        ok ?= verify_no_processes(BasePath),
        ok ?= verify_no_processes(InitPath),
        %% 4. Enable controllers on BasePath (for beam/ and containers/)
        ok ?= enable_controllers(BasePath),
        %% 5. Enable controllers on containers/ (for container subdirs)
        ok ?= enable_controllers(ContainersPath),
        %% 6. Apply limits to beam/
        ok ?= apply_beam_limits(BeamPath),
        %% 7. Apply ceiling to containers/
        ok ?= apply_containers_ceiling(ContainersPath),
        %% 8. Determine config source for logging
        BeamCfg = beam_config(),
        ContainersCfg = containers_config(),
        Source = config_source(),
        log_protection_config(BeamCfg, ContainersCfg, Source),
        {ok, BeamPath, ContainersPath}
    else
        {error, _} = Err -> Err
    end.

-spec ensure_dir(string()) -> ok | {error, term()}.
ensure_dir(Path) ->
    case file:make_dir(Path) of
        ok              -> ok;
        {error, eexist} -> ok;
        {error, Reason} ->
            logger:error("erlkoenig_cgroup: make_dir ~s failed: ~p", [Path, Reason]),
            {error, Reason}
    end.

%% Move ALL processes from SourcePath to TargetPath.
%% This satisfies the cgroups v2 "no internal process" rule:
%% a cgroup with subtree_control enabled cannot have member processes.
-spec move_processes_to(string(), string()) -> ok | {error, term()}.
move_processes_to(SourcePath, TargetPath) ->
    SourceProcs = filename:join(SourcePath, "cgroup.procs"),
    TargetProcs = filename:join(TargetPath, "cgroup.procs"),
    case file:read_file(SourceProcs) of
        {ok, Bin} ->
            Pids = [P || P <- binary:split(Bin, <<"\n">>, [global]),
                        P =/= <<>>],
            case Pids of
                [] ->
                    ok;
                _ ->
                    logger:info("erlkoenig_cgroup: moving ~b pids from ~s to ~s",
                                [length(Pids), SourcePath, TargetPath]),
                    lists:foreach(fun(Pid) ->
                        _ = file:write_file(TargetProcs, Pid)
                    end, Pids),
                    ok
            end;
        {error, enoent} ->
            %% Source cgroup doesn't exist (e.g. no init/ subgroup) — skip
            ok;
        {error, Reason} ->
            logger:error("erlkoenig_cgroup: read ~s failed: ~p",
                         [SourceProcs, Reason]),
            {error, Reason}
    end.

%% Verify that no processes remain in a cgroup.
%% This is a hard requirement — if processes remain, enabling
%% subtree_control will fail with EBUSY.
-spec verify_no_processes(string()) -> ok | {error, term()}.
verify_no_processes(BasePath) ->
    ProcsFile = filename:join(BasePath, "cgroup.procs"),
    case file:read_file(ProcsFile) of
        {ok, Bin} ->
            Pids = [P || P <- binary:split(Bin, <<"\n">>, [global]),
                        P =/= <<>>],
            case Pids of
                [] -> ok;
                _  ->
                    logger:error("erlkoenig_cgroup: ~b processes remain in ~s after move",
                                 [length(Pids), BasePath]),
                    {error, processes_remain_in_base}
            end;
        {error, enoent} ->
            %% Cgroup doesn't exist (e.g. init/ was never created) — ok
            ok;
        {error, Reason} ->
            logger:error("erlkoenig_cgroup: read cgroup.procs ~s failed: ~p",
                         [BasePath, Reason]),
            {error, Reason}
    end.

%% Enable controllers in a cgroup so child cgroups can use them.
-spec enable_controllers(string()) -> ok | {error, term()}.
enable_controllers(BasePath) ->
    SubtreeControl = filename:join(BasePath, "cgroup.subtree_control"),
    case file:write_file(SubtreeControl, "+cpu +memory +pids") of
        ok    -> ok;
        Error -> Error
    end.

%% Apply beam protection limits — hard init step.
-spec apply_beam_limits(string()) -> ok | {error, term()}.
apply_beam_limits(BeamPath) ->
    Cfg = beam_config(),
    maybe
        ok ?= write_cgroup_file(BeamPath, "memory.min",
                                integer_to_list(maps:get(memory_min, Cfg))),
        ok ?= write_cgroup_file(BeamPath, "memory.max",
                                integer_to_list(maps:get(memory_max, Cfg))),
        ok ?= write_cgroup_file(BeamPath, "cpu.weight",
                                integer_to_list(maps:get(cpu_weight, Cfg))),
        ok ?= write_cgroup_file(BeamPath, "pids.max",
                                integer_to_list(maps:get(pids_max, Cfg)))
    else
        {error, _} = Err -> Err
    end.

%% Apply containers ceiling limits — hard init step.
-spec apply_containers_ceiling(string()) -> ok | {error, term()}.
apply_containers_ceiling(ContainersPath) ->
    Cfg = containers_config(),
    maybe
        ok ?= write_cgroup_file(ContainersPath, "memory.max",
                                integer_to_list(maps:get(memory_max, Cfg))),
        ok ?= write_cgroup_file(ContainersPath, "pids.max",
                                integer_to_list(maps:get(pids_max, Cfg)))
    else
        {error, _} = Err -> Err
    end.

%% Write a value to a cgroup control file.
-spec write_cgroup_file(string(), string(), string()) -> ok | {error, term()}.
write_cgroup_file(CgroupPath, Filename, Value) ->
    File = filename:join(CgroupPath, Filename),
    case file:write_file(File, Value) of
        ok -> ok;
        {error, Reason} ->
            logger:error("erlkoenig_cgroup: write ~s failed: ~p", [File, Reason]),
            {error, Reason}
    end.

%% Determine the source of configuration for logging.
-spec config_source() -> string().
config_source() ->
    case application:get_env(erlkoenig, resource_protection) of
        undefined -> "defaults";
        {ok, Cfg} ->
            case maps:get(containers_memory_max, Cfg, auto) of
                auto -> "auto";
                _    -> "sys.config"
            end
    end.

%% Format bytes as a human-readable string.
-spec format_bytes(non_neg_integer()) -> string().
format_bytes(Bytes) when Bytes >= 1_073_741_824 ->
    io_lib:format("~.1fG", [Bytes / 1_073_741_824]);
format_bytes(Bytes) when Bytes >= 1_048_576 ->
    io_lib:format("~.1fM", [Bytes / 1_048_576]);
format_bytes(Bytes) when Bytes >= 1024 ->
    io_lib:format("~.1fK", [Bytes / 1024]);
format_bytes(Bytes) ->
    io_lib:format("~bB", [Bytes]).

%% -- Stats readers ---------------------------------------------------

-spec read_memory_current(string(), map()) -> map().
read_memory_current(Path, Acc) ->
    read_int_file(Path, "memory.current", memory_bytes, Acc).

-spec read_memory_peak(string(), map()) -> map().
read_memory_peak(Path, Acc) ->
    read_int_file(Path, "memory.peak", memory_peak, Acc).

-spec read_pids_current(string(), map()) -> map().
read_pids_current(Path, Acc) ->
    read_int_file(Path, "pids.current", pids_current, Acc).

-spec read_cpu_stat(string(), map()) -> map().
read_cpu_stat(Path, Acc) ->
    File = filename:join(Path, "cpu.stat"),
    case file:read_file(File) of
        {ok, Bin} ->
            case parse_cpu_usage(Bin) of
                {ok, Usec} -> Acc#{cpu_usec => Usec};
                error       -> Acc
            end;
        _ ->
            Acc
    end.

-spec read_int_file(string(), string(), atom(), map()) -> map().
read_int_file(Path, Filename, Key, Acc) ->
    File = filename:join(Path, Filename),
    case file:read_file(File) of
        {ok, Bin} ->
            try binary_to_integer(string:trim(Bin)) of
                N -> Acc#{Key => N}
            catch _:_ -> Acc
            end;
        _ ->
            Acc
    end.

-spec parse_cpu_usage(binary()) -> {ok, non_neg_integer()} | error.
parse_cpu_usage(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    parse_cpu_usage_lines(Lines).

-spec parse_cpu_usage_lines([binary()]) -> {ok, non_neg_integer()} | error.
parse_cpu_usage_lines([]) -> error;
parse_cpu_usage_lines([Line | Rest]) ->
    case binary:split(Line, <<" ">>) of
        [<<"usage_usec">>, Val] ->
            try {ok, binary_to_integer(string:trim(Val))}
            catch _:_ -> error
            end;
        _ ->
            parse_cpu_usage_lines(Rest)
    end.

-spec parse_oom_kill(binary()) -> boolean().
parse_oom_kill(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    lists:any(fun
        (<<"oom_kill ", Val/binary>>) ->
            try binary_to_integer(string:trim(Val)) > 0
            catch _:_ -> false
            end;
        (_) -> false
    end, Lines).

-spec apply_limit(string(), atom(), term()) -> [ok | {error, term()}].
apply_limit(_Path, _Type, undefined) ->
    [];
apply_limit(Path, memory, Bytes) when is_integer(Bytes), Bytes > 0 ->
    File = filename:join(Path, "memory.max"),
    [file:write_file(File, integer_to_list(Bytes))];
apply_limit(Path, cpu, Percent) when is_number(Percent), Percent > 0, Percent =< 100 ->
    %% cpu.max takes "QUOTA PERIOD" in microseconds.
    %% For 50% of one core: "500000 1000000"
    Quota = round(Percent / 100 * ?CPU_PERIOD),
    Value = integer_to_list(Quota) ++ " " ++ integer_to_list(?CPU_PERIOD),
    File = filename:join(Path, "cpu.max"),
    [file:write_file(File, Value)];
apply_limit(Path, pids, Max) when is_integer(Max), Max > 0 ->
    File = filename:join(Path, "pids.max"),
    [file:write_file(File, integer_to_list(Max))];
apply_limit(_Path, Type, Value) ->
    [{error, {invalid_limit, Type, Value}}].
