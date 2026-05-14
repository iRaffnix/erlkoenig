%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_node_resources).
-moduledoc """
Single-node resource accounting for Phase-B admission control.

Maintains an ETS snapshot of aggregate container capacity and an
in-memory committed map for containers admitted but not yet running.
`admit/2` performs the capacity check and commit in one gen_server
call, so parallel spawns cannot double-book the same headroom.
""".

-behaviour(gen_server).

-export([start_link/0,
         get_capacity/0,
         admit/2,
         commit/2,
         confirm_running/1,
         release_commit/1,
         snapshot_from/2,
         parse_meminfo/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(TABLE, ?MODULE).
-define(DEFAULT_INTERVAL_MS, 2_000).
%% Keep this below the snapshot interval so one unhealthy container cannot
%% stall the resource loop, but high enough for healthy lifecycle states that
%% are briefly busy with spawn/network setup on real hosts.
-define(CT_INFO_TIMEOUT_MS, 500).
-define(DEFAULT_CONTAINERS_MAX, 10_000).
-define(BEAM_MEMORY_PRESSURE_BYTES, 400_000_000).
-define(BEAM_PROCESS_PRESSURE, 100_000).

-record(state, {
    memory_total       = 0 :: non_neg_integer(),
    pid_max            = 0 :: non_neg_integer(),
    cpu_cores          = 1 :: pos_integer(),
    containers_ceiling = 0 :: non_neg_integer(),
    containers_pids    = 0 :: non_neg_integer(),
    containers_max     = ?DEFAULT_CONTAINERS_MAX :: pos_integer(),
    require_mem        = true :: boolean(),
    require_pids       = true :: boolean(),
    committed          = #{} :: #{binary() => map()},
    tref               = undefined :: reference() | undefined
}).

-type denial_reason() :: #{
    reason := atom(),
    atom() => term()
}.

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-doc "Fast ETS read of the latest capacity snapshot.".
-spec get_capacity() -> map().
get_capacity() ->
    case ets:info(?TABLE) of
        undefined -> #{};
        _ ->
            case ets:lookup(?TABLE, capacity) of
                [{capacity, Cap}] -> Cap;
                [] -> #{}
            end
    end.

-doc "Atomically check capacity and reserve resources for a spawning container.".
-spec admit(binary(), map()) -> ok | {error, denial_reason()}.
admit(Id, Limits) when is_binary(Id), is_map(Limits) ->
    gen_server:call(?SERVER, {admit, Id, Limits}).

-doc "Reserve resources without checks. Exposed for compatibility with the spec.".
-spec commit(binary(), map()) -> ok.
commit(Id, Limits) when is_binary(Id), is_map(Limits) ->
    gen_server:call(?SERVER, {commit, Id, Limits}).

-doc "Container reached running; committed reservation can be removed.".
-spec confirm_running(binary()) -> ok.
confirm_running(Id) when is_binary(Id) ->
    gen_server:call(?SERVER, {confirm_running, Id}).

-doc "Spawn failed; committed reservation can be removed. Idempotent.".
-spec release_commit(binary()) -> ok.
release_commit(Id) when is_binary(Id) ->
    gen_server:call(?SERVER, {release_commit, Id}).

-doc "Pure snapshot builder for tests.".
-spec snapshot_from(#state{}, map()) -> map().
snapshot_from(State, Dynamic) ->
    Allocated = maps:get(allocated, Dynamic, #{}),
    Committed = committed_totals(State#state.committed),
    Running = maps:get(containers_running, Allocated, 0),
    MemoryAllocated = maps:get(memory, Allocated, 0),
    PidsAllocated = maps:get(pids, Allocated, 0),
    MemoryCommitted = maps:get(memory, Committed, 0),
    PidsCommitted = maps:get(pids, Committed, 0),
    #{
        memory_total => State#state.memory_total,
        pid_max => State#state.pid_max,
        cpu_cores => State#state.cpu_cores,
        containers_ceiling => State#state.containers_ceiling,
        containers_pids_max => State#state.containers_pids,
        containers_max => State#state.containers_max,
        require_memory_limit => State#state.require_mem,
        require_pids_limit => State#state.require_pids,
        memory_available => maps:get(memory_available, Dynamic, 0),
        memory_allocated => MemoryAllocated,
        memory_committed => MemoryCommitted,
        memory_allocated_sources => maps:get(memory_sources, Allocated, []),
        memory_committed_sources => maps:get(memory_sources, Committed, []),
        pids_allocated => PidsAllocated,
        pids_committed => PidsCommitted,
        pids_allocated_sources => maps:get(pids_sources, Allocated, []),
        pids_committed_sources => maps:get(pids_sources, Committed, []),
        allocated_read_errors => maps:get(read_errors, Allocated, []),
        containers_running => Running,
        beam_memory => maps:get(beam_memory, Dynamic, erlang:memory(total)),
        beam_processes => maps:get(beam_processes, Dynamic,
                                   erlang:system_info(process_count)),
        allocatable_memory => max(0, State#state.containers_ceiling
                                     - MemoryAllocated - MemoryCommitted),
        allocatable_pids => max(0, State#state.containers_pids
                                   - PidsAllocated - PidsCommitted),
        last_updated => erlang:system_time(millisecond)
    }.

-spec parse_meminfo(binary()) -> {ok, map()} | {error, term()}.
parse_meminfo(Bin) ->
    Lines = binary:split(Bin, <<"\n">>, [global]),
    Parsed = lists:foldl(fun parse_meminfo_line/2, #{}, Lines),
    case maps:find(memory_total, Parsed) of
        {ok, _} -> {ok, Parsed};
        error -> {error, memtotal_missing}
    end.

init([]) ->
    ensure_table(),
    Mem = read_meminfo_snapshot(),
    CGroup = erlkoenig_cgroup:containers_config(),
    Cfg = application:get_env(erlkoenig, resource_protection, #{}),
    State0 = #state{
        memory_total = maps:get(memory_total, Mem, 0),
        pid_max = read_pid_max(),
        cpu_cores = max(1, erlang:system_info(logical_processors)),
        containers_ceiling = maps:get(memory_max, CGroup),
        containers_pids = maps:get(pids_max, CGroup),
        containers_max = maps:get(containers_max, Cfg, ?DEFAULT_CONTAINERS_MAX),
        require_mem = maps:get(require_memory_limit, Cfg, true),
        require_pids = maps:get(require_pids_limit, Cfg, true)
    },
    State = publish_snapshot(State0),
    {ok, State}.

handle_call({admit, Id, Limits}, _From, State) ->
    Cap = current_capacity(State),
    case check_admission(Limits, Cap) of
        ok ->
            State2 = commit_in_state(Id, Limits, State),
            State3 = publish_snapshot(State2),
            {reply, ok, State3};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    end;
handle_call({commit, Id, Limits}, _From, State) ->
    State2 = publish_snapshot(commit_in_state(Id, Limits, State)),
    {reply, ok, State2};
handle_call({confirm_running, Id}, _From, State) ->
    State2 = publish_snapshot(remove_commit(Id, State)),
    {reply, ok, State2};
handle_call({release_commit, Id}, _From, State) ->
    State2 = publish_snapshot(remove_commit(Id, State)),
    {reply, ok, State2};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(tick, State) ->
    {noreply, publish_snapshot(State)};
handle_info(_, State) ->
    {noreply, State}.

terminate(_Reason, #state{tref = TRef}) ->
    _ = cancel_timer(TRef),
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

-spec current_capacity(#state{}) -> map().
current_capacity(State) ->
    snapshot_from(State, dynamic_snapshot()).

-spec publish_snapshot(#state{}) -> #state{}.
publish_snapshot(#state{tref = OldRef} = State) ->
    _ = cancel_timer(OldRef),
    Cap = current_capacity(State),
    ets:insert(?TABLE, {capacity, Cap}),
    State#state{tref = erlang:send_after(?DEFAULT_INTERVAL_MS, self(), tick)}.

-spec dynamic_snapshot() -> map().
dynamic_snapshot() ->
    Mem = read_meminfo_snapshot(),
    Allocated = allocated_from_running(),
    #{memory_available => maps:get(memory_available, Mem, 0),
      allocated => Allocated,
      containers_running => maps:get(containers_running, Allocated, 0),
      beam_memory => erlang:memory(total),
      beam_processes => erlang:system_info(process_count)}.

-spec allocated_from_running() -> map().
allocated_from_running() ->
    {Members, ReadErrors} =
        try {pg:get_members(erlkoenig_pg, erlkoenig_cts), []}
        catch Class:Reason ->
            logger:warning("node_resources: pg member read failed ~p:~p; "
                           "marking capacity snapshot degraded",
                           [Class, Reason]),
            {[], [#{source => pg, class => Class, reason => Reason}]}
        end,
    fold_allocated_members(Members,
                           #{memory => 0, pids => 0, containers_running => 0,
                             memory_sources => [], pids_sources => [],
                             read_errors => ReadErrors}).

fold_allocated_members(_Members, #{read_errors := [_ | _]} = Acc) ->
    Acc;
fold_allocated_members([], Acc) ->
    Acc;
fold_allocated_members([Pid | Rest], Acc) ->
    fold_allocated_members(Rest, allocated_one(Pid, Acc)).

allocated_one(Pid, Acc) when is_pid(Pid) ->
    try erlkoenig_ct:get_info(Pid, ?CT_INFO_TIMEOUT_MS) of
        #{id := Id, limits := Limits} = Info when is_map(Limits) ->
            Name = maps:get(name, Info, undefined),
            Memory = positive_limit(memory, Limits),
            Pids = positive_limit(pids, Limits),
            Acc#{memory := maps:get(memory, Acc) + Memory,
                 pids := maps:get(pids, Acc) + Pids,
                 memory_sources := add_source(memory, Id, Name, Memory,
                                               undefined,
                                               maps:get(memory_sources, Acc)),
                 pids_sources := add_source(pids, Id, Name, Pids,
                                            undefined,
                                            maps:get(pids_sources, Acc)),
                 containers_running := maps:get(containers_running, Acc) + 1};
        Other ->
            add_read_error(Pid, bad_info_shape, Other, Acc)
    catch
        exit:{timeout, _} ->
            logger:warning("node_resources: ct ~p get_info timeout after ~p ms; "
                           "marking capacity snapshot degraded",
                           [Pid, ?CT_INFO_TIMEOUT_MS]),
            add_read_error(Pid, timeout, ?CT_INFO_TIMEOUT_MS, Acc);
        Class:Reason ->
            logger:warning("node_resources: ct ~p get_info failed ~p:~p; "
                           "marking capacity snapshot degraded",
                           [Pid, Class, Reason]),
            add_read_error(Pid, {Class, Reason}, undefined, Acc)
    end.

-spec check_admission(map(), map()) -> ok | {error, denial_reason()}.
check_admission(Limits, Cap) ->
    maybe
        ok ?= check_snapshot_health(Cap),
        ok ?= check_beam_health(Cap),
        ok ?= check_limits_declared(Limits, Cap),
        ok ?= check_memory(Limits, Cap),
        ok ?= check_pids(Limits, Cap),
        ok ?= check_container_count(Cap),
        ok
    end.

check_snapshot_health(Cap) ->
    case maps:get(allocated_read_errors, Cap, []) of
        [] ->
            ok;
        Errors ->
            {error, #{
                reason => node_resources_unavailable,
                cause => allocated_snapshot_degraded,
                read_errors => Errors,
                last_updated => maps:get(last_updated, Cap, undefined)
            }}
    end.

check_beam_health(#{beam_memory := BeamMem, beam_processes := BeamProcs}) ->
    if
        BeamMem > ?BEAM_MEMORY_PRESSURE_BYTES ->
            {error, #{reason => beam_memory_pressure,
                      current => BeamMem,
                      threshold => ?BEAM_MEMORY_PRESSURE_BYTES}};
        BeamProcs > ?BEAM_PROCESS_PRESSURE ->
            {error, #{reason => beam_process_pressure,
                      current => BeamProcs,
                      threshold => ?BEAM_PROCESS_PRESSURE}};
        true -> ok
    end.

check_limits_declared(Limits, Cap) ->
    RequireMem = maps:get(require_memory_limit, Cap, true),
    RequirePids = maps:get(require_pids_limit, Cap, true),
    HasMem = positive_limit(memory, Limits) > 0,
    HasPids = positive_limit(pids, Limits) > 0,
    if
        RequireMem andalso not HasMem ->
            {error, #{reason => no_memory_limit_declared,
                      required => true}};
        RequirePids andalso not HasPids ->
            {error, #{reason => no_pids_limit_declared,
                      required => true}};
        true -> ok
    end.

check_memory(Limits, #{allocatable_memory := Available} = Cap) ->
    Required = positive_limit(memory, Limits),
    case Required =< Available of
        true -> ok;
        false ->
            {error, #{reason => insufficient_memory,
                      required => Required,
                      available => Available,
                      evidence => denial_evidence(memory, Cap)}}
    end.

check_pids(Limits, #{allocatable_pids := Available} = Cap) ->
    Required = positive_limit(pids, Limits),
    case Required =< Available of
        true -> ok;
        false ->
            {error, #{reason => insufficient_pids,
                      required => Required,
                      available => Available,
                      evidence => denial_evidence(pids, Cap)}}
    end.

check_container_count(#{containers_running := Running, containers_max := Max}) ->
    case Running < Max of
        true -> ok;
        false ->
            {error, #{reason => container_limit_reached,
                      running => Running,
                      max => Max}}
    end.

commit_in_state(Id, Limits, #state{committed = C} = State) ->
    Entry = #{memory => positive_limit(memory, Limits),
              pids => positive_limit(pids, Limits),
              since_ms => erlang:system_time(millisecond)},
    State#state{committed = C#{Id => Entry}}.

remove_commit(Id, #state{committed = C} = State) ->
    State#state{committed = maps:remove(Id, C)}.

committed_totals(Committed) ->
    maps:fold(fun(Id, Entry, Acc) ->
        Memory = maps:get(memory, Entry, 0),
        Pids = maps:get(pids, Entry, 0),
        SinceMs = maps:get(since_ms, Entry, undefined),
        Acc#{memory := maps:get(memory, Acc) + Memory,
             pids := maps:get(pids, Acc) + Pids,
             memory_sources := add_source(memory, Id, undefined, Memory,
                                           SinceMs,
                                           maps:get(memory_sources, Acc)),
             pids_sources := add_source(pids, Id, undefined, Pids,
                                        SinceMs,
                                        maps:get(pids_sources, Acc))}
    end, #{memory => 0, pids => 0,
           memory_sources => [], pids_sources => []}, Committed).

add_source(_Kind, _Id, _Name, Value, _SinceMs, Sources) when Value =< 0 ->
    Sources;
add_source(Kind, Id, Name, Value, SinceMs, Sources) ->
    Source0 = #{id => Id, kind => Kind, value => Value},
    Source1 =
        case Name of
            undefined -> Source0;
            _ -> Source0#{name => Name}
        end,
    Source =
        case SinceMs of
            undefined -> Source1;
            _ -> Source1#{since_ms => SinceMs}
        end,
    [Source | Sources].

add_read_error(Pid, Reason, Detail, Acc) ->
    Error0 = #{pid => Pid, reason => Reason},
    Error =
        case Detail of
            undefined -> Error0;
            _ -> Error0#{detail => Detail}
        end,
    Acc#{read_errors := [Error | maps:get(read_errors, Acc)]}.

denial_evidence(memory, Cap) ->
    #{
        kind => memory,
        ceiling => maps:get(containers_ceiling, Cap, 0),
        allocated => maps:get(memory_allocated, Cap, 0),
        committed => maps:get(memory_committed, Cap, 0),
        allocated_sources => maps:get(memory_allocated_sources, Cap, []),
        committed_sources => maps:get(memory_committed_sources, Cap, []),
        last_updated => maps:get(last_updated, Cap, undefined)
    };
denial_evidence(pids, Cap) ->
    #{
        kind => pids,
        ceiling => maps:get(containers_pids_max, Cap, 0),
        allocated => maps:get(pids_allocated, Cap, 0),
        committed => maps:get(pids_committed, Cap, 0),
        allocated_sources => maps:get(pids_allocated_sources, Cap, []),
        committed_sources => maps:get(pids_committed_sources, Cap, []),
        last_updated => maps:get(last_updated, Cap, undefined)
    }.

positive_limit(Key, Limits) ->
    case maps:get(Key, Limits, 0) of
        N when is_integer(N), N > 0 -> N;
        _ -> 0
    end.

ensure_table() ->
    case ets:info(?TABLE) of
        undefined ->
            ets:new(?TABLE, [named_table, public, set, {read_concurrency, true}]);
        _ ->
            ok
    end.

read_meminfo_snapshot() ->
    case file:read_file("/proc/meminfo") of
        {ok, Bin} ->
            case parse_meminfo(Bin) of
                {ok, Map} -> Map;
                {error, _} -> #{}
            end;
        {error, _} ->
            #{}
    end.

parse_meminfo_line(<<"MemTotal:", Rest/binary>>, Acc) ->
    parse_kb(Rest, memory_total, Acc);
parse_meminfo_line(<<"MemAvailable:", Rest/binary>>, Acc) ->
    parse_kb(Rest, memory_available, Acc);
parse_meminfo_line(_Line, Acc) ->
    Acc.

parse_kb(Rest, Key, Acc) ->
    case binary:split(string:trim(Rest), <<" ">>, [global, trim_all]) of
        [KB, <<"kB">> | _] ->
            try binary_to_integer(KB) of
                N -> Acc#{Key => N * 1024}
            catch _:_ -> Acc
            end;
        _ ->
            Acc
    end.

read_pid_max() ->
    case file:read_file("/proc/sys/kernel/pid_max") of
        {ok, Bin} ->
            try binary_to_integer(string:trim(Bin)) of
                N -> N
            catch _:_ -> 0
            end;
        {error, _} ->
            0
    end.

cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> _ = erlang:cancel_timer(Ref), ok.
