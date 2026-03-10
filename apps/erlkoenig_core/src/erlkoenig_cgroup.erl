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
%%% @doc erlkoenig_cgroup - cgroups v2 resource limits per container.
%%%
%%% Manages a cgroup hierarchy for erlkoenig containers.
%%% Each container gets a sub-cgroup named by its ID.
%%%
%%% The base cgroup path is auto-detected:
%%%   - Under systemd with Delegate=yes: uses the delegated cgroup
%%%     (e.g. /sys/fs/cgroup/system.slice/erlkoenig.service/erlkoenig/)
%%%   - Running as root: /sys/fs/cgroup/erlkoenig/
%%%
%%% Supported limits (all optional):
%%%   memory  - Max memory in bytes (written to memory.max)
%%%   cpu     - CPU percentage of one core, 1-100 (written to cpu.max)
%%%   pids    - Max number of processes (written to pids.max)
%%%
%%% The gen_server creates the top-level cgroup on init and enables
%%% the required controllers. On terminate, it removes the top-level
%%% cgroup (only succeeds if all containers are cleaned up).
%%%
%%% All operations are pure file I/O on cgroupfs — no os:cmd.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_cgroup).

-behaviour(gen_server).

%% API
-export([start_link/0,
         create/1,
         attach/2,
         set_limits/2,
         destroy/1,
         read_stats/1,
         was_oom_killed/1,
         path/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(CGROUP_ROOT, "/sys/fs/cgroup").

%% CPU period in microseconds (fixed at 1 second).
-define(CPU_PERIOD, 1_000_000).

-record(state, {
    base_path :: string()   %% e.g. "/sys/fs/cgroup/system.slice/erlkoenig.service/erlkoenig"
}).

%% =================================================================
%% API
%% =================================================================

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Create a cgroup for a container.
-spec create(binary()) -> ok | {error, term()}.
create(ContainerId) ->
    gen_server:call(?MODULE, {create, ContainerId}).

%% @doc Move a process into a container's cgroup.
-spec attach(binary(), non_neg_integer()) -> ok | {error, term()}.
attach(ContainerId, OsPid) ->
    gen_server:call(?MODULE, {attach, ContainerId, OsPid}).

%% @doc Set resource limits for a container.
%%
%% Limits is a map with optional keys:
%%   memory => Bytes      (e.g. 64_000_000 for 64 MB)
%%   cpu    => Percent     (e.g. 50 for 50% of one core)
%%   pids   => MaxPids    (e.g. 64)
-spec set_limits(binary(), map()) -> ok | {error, term()}.
set_limits(ContainerId, Limits) ->
    gen_server:call(?MODULE, {set_limits, ContainerId, Limits}).

%% @doc Remove a container's cgroup.
%%
%% The cgroup must be empty (no processes). Deleting a cgroup with
%% processes still in it will fail with EBUSY.
-spec destroy(binary()) -> ok | {error, term()}.
destroy(ContainerId) ->
    gen_server:call(?MODULE, {destroy, ContainerId}).

%% @doc Read live resource stats from a container's cgroup.
-spec read_stats(binary()) -> {ok, map()} | {error, term()}.
read_stats(ContainerId) ->
    gen_server:call(?MODULE, {read_stats, ContainerId}).

%% @doc Check if a container was OOM-killed by reading memory.events.
-spec was_oom_killed(binary()) -> boolean().
was_oom_killed(ContainerId) ->
    gen_server:call(?MODULE, {was_oom_killed, ContainerId}).

%% @doc Get the absolute cgroup directory path for a container.
-spec path(binary()) -> {ok, string()} | {error, term()}.
path(ContainerId) ->
    gen_server:call(?MODULE, {path, ContainerId}).

%% =================================================================
%% gen_server callbacks
%% =================================================================

init([]) ->
    process_flag(trap_exit, true),
    BasePath = detect_base_path(),
    logger:info("erlkoenig_cgroup: detected base path ~s", [BasePath]),
    case setup_top_level_cgroup(BasePath) of
        ok ->
            logger:info("erlkoenig_cgroup: setup complete at ~s", [BasePath]),
            {ok, #state{base_path = BasePath}};
        {error, Reason} ->
            logger:error("erlkoenig_cgroup: setup failed at ~s: ~p", [BasePath, Reason]),
            {stop, {cgroup_setup_failed, Reason}}
    end.

handle_call({create, ContainerId}, _From, #state{base_path = Base} = State) ->
    Path = container_path(Base, ContainerId),
    Result = case file:make_dir(Path) of
        ok              -> ok;
        {error, eexist} -> ok;
        Error           -> Error
    end,
    {reply, Result, State};

handle_call({attach, ContainerId, OsPid}, _From, #state{base_path = Base} = State) ->
    Path = filename:join(container_path(Base, ContainerId), "cgroup.procs"),
    Result = file:write_file(Path, integer_to_list(OsPid)),
    {reply, Result, State};

handle_call({set_limits, ContainerId, Limits}, _From, #state{base_path = Base} = State) ->
    Path = container_path(Base, ContainerId),
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

handle_call({destroy, ContainerId}, _From, #state{base_path = Base} = State) ->
    Path = container_path(Base, ContainerId),
    Result = case file:del_dir(Path) of
        ok              -> ok;
        {error, enoent} -> ok;
        Error           -> Error
    end,
    {reply, Result, State};

handle_call({read_stats, ContainerId}, _From, #state{base_path = Base} = State) ->
    Path = container_path(Base, ContainerId),
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

handle_call({was_oom_killed, ContainerId}, _From, #state{base_path = Base} = State) ->
    Path = container_path(Base, ContainerId),
    File = filename:join(Path, "memory.events"),
    Result = case file:read_file(File) of
        {ok, Bin} -> parse_oom_kill(Bin);
        _         -> false
    end,
    {reply, Result, State};

handle_call({path, ContainerId}, _From, #state{base_path = Base} = State) ->
    Path = container_path(Base, ContainerId),
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

terminate(_Reason, #state{base_path = BasePath}) ->
    %% Best-effort removal of cgroup hierarchy.
    %% init/ may have our processes — can't delete while running.
    %% Container cgroups should already be cleaned up.
    _ = file:del_dir(filename:join(BasePath, "init")),
    _ = file:del_dir(BasePath),
    ok.

%% =================================================================
%% Internal
%% =================================================================

-spec container_path(string(), binary()) -> string().
container_path(BasePath, ContainerId) when is_binary(ContainerId) ->
    filename:join(BasePath, binary_to_list(ContainerId)).

%% @doc Auto-detect the cgroup base path.
%%
%% Under systemd with Delegate=yes, the process runs in a delegated
%% cgroup like /sys/fs/cgroup/system.slice/erlkoenig.service/.
%% We use that directly as the base path for container cgroups.
%%
%% When running as root (or in the root cgroup), we create
%% /sys/fs/cgroup/erlkoenig/ as a dedicated cgroup.
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
                    %% Strip trailing "/init" — that's the child cgroup we create
                    %% in maybe_move_self_to_init/1 to satisfy the "no internal
                    %% process" rule. The base path is the parent.
                    BaseCgroup = case lists:suffix("/init", CgroupPath) of
                        true  -> lists:sublist(CgroupPath, length(CgroupPath) - 5);
                        false -> CgroupPath
                    end,
                    ?CGROUP_ROOT ++ BaseCgroup;
                error ->
                    filename:join(?CGROUP_ROOT, "erlkoenig")
            end;
        _ ->
            filename:join(?CGROUP_ROOT, "erlkoenig")
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

-spec setup_top_level_cgroup(string()) -> ok | {error, term()}.
setup_top_level_cgroup(BasePath) ->
    %% Ensure the base cgroup directory exists.
    case ensure_dir(BasePath) of
        ok ->
            %% cgroups v2 "no internal process" rule: a cgroup that has
            %% controllers enabled via subtree_control cannot also have
            %% member processes. Move BEAM to a child cgroup first.
            case maybe_move_self_to_init(BasePath) of
                ok ->
                    enable_controllers(BasePath);
                {error, _} = Err ->
                    Err
            end;
        {error, _} = Err ->
            Err
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

%% Move ALL processes from BasePath to an "init" child cgroup.
%% This is needed for systemd-delegated cgroups where the BEAM
%% (and erl_child_setup) starts in the delegated cgroup.
%% Without this, enabling subtree_control would fail with EBUSY
%% due to the "no internal process" rule.
-spec maybe_move_self_to_init(string()) -> ok | {error, term()}.
maybe_move_self_to_init(BasePath) ->
    InitPath = filename:join(BasePath, "init"),
    case ensure_dir(InitPath) of
        ok ->
            %% Read all PIDs currently in the parent cgroup
            ParentProcs = filename:join(BasePath, "cgroup.procs"),
            InitProcs = filename:join(InitPath, "cgroup.procs"),
            case file:read_file(ParentProcs) of
                {ok, Bin} ->
                    Pids = [P || P <- binary:split(Bin, <<"\n">>, [global]),
                                P =/= <<>>],
                    logger:info("erlkoenig_cgroup: moving ~b pids to ~s",
                                [length(Pids), InitPath]),
                    %% Move each PID to the init cgroup
                    lists:foreach(fun(Pid) ->
                        _ = file:write_file(InitProcs, Pid)
                    end, Pids),
                    ok;
                {error, Reason} ->
                    logger:error("erlkoenig_cgroup: read cgroup.procs failed: ~p",
                                 [Reason]),
                    {error, Reason}
            end;
        {error, _} = Err ->
            Err
    end.

%% Enable controllers in the top-level cgroup so child cgroups
%% can use them.
-spec enable_controllers(string()) -> ok | {error, term()}.
enable_controllers(BasePath) ->
    SubtreeControl = filename:join(BasePath, "cgroup.subtree_control"),
    case file:write_file(SubtreeControl, "+cpu +memory +pids") of
        ok    -> ok;
        Error -> Error
    end.

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
