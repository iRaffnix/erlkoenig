%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%%

-module(erlkoenig_cgroup_stats).
-moduledoc """
Periodic aggregate cgroup headroom emitter for the containers/ subtree.

Reads `erlkoenig_cgroup:read_containers_stats/0`, derives memory and
PID headroom from the aggregate `memory.max` and `pids.max`, and emits
`{containers_stats, Payload}` through `erlkoenig_events`.

Configuration lives in `resource_protection`:

`containers_stats_enabled` — defaults to `true`.
`containers_stats_interval_ms` — defaults to 60000, floored at 1000.
""".

-behaviour(gen_server).

-export([start_link/0,
         poll_now/0,
         payload/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_INTERVAL_MS, 60_000).
-define(MIN_INTERVAL_MS, 1_000).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-doc "Force an immediate aggregate cgroup poll and emit cycle.".
-spec poll_now() -> {ok, emitted | skipped | {error, term()}}.
poll_now() ->
    gen_server:call(?SERVER, poll_now, 30_000).

-doc "Build the operator payload from raw containers/ cgroup stats.".
-spec payload(map()) -> map().
payload(Stats) ->
    MemoryCurrent = maps:get(memory_bytes, Stats, 0),
    MemoryMax = maps:get(memory_max, Stats, max),
    PidsCurrent = maps:get(pids_current, Stats, 0),
    PidsMax = maps:get(pids_max, Stats, max),
    Base = #{
        scope => containers,
        ts_ms => erlang:system_time(millisecond),
        memory_current => MemoryCurrent,
        memory_peak => maps:get(memory_peak, Stats, 0),
        memory_max => MemoryMax,
        cpu_usec => maps:get(cpu_usec, Stats, 0),
        pids_current => PidsCurrent,
        pids_max => PidsMax
    },
    with_pids_headroom(with_memory_headroom(Base, MemoryCurrent, MemoryMax),
                       PidsCurrent, PidsMax).

init([]) ->
    Cfg = application:get_env(erlkoenig, resource_protection, #{}),
    Interval = read_interval(Cfg),
    Enabled = maps:get(containers_stats_enabled, Cfg, true),
    State = #{interval => Interval, enabled => Enabled},
    schedule_next(Interval),
    {ok, State}.

handle_call(poll_now, _From, State) ->
    {reply, do_poll(), State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(poll, #{interval := Interval, enabled := true} = State) ->
    _ = do_poll(),
    schedule_next(Interval),
    {noreply, State};
handle_info(poll, #{interval := Interval} = State) ->
    schedule_next(Interval),
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

-spec read_interval(map()) -> pos_integer().
read_interval(Cfg) ->
    Requested = maps:get(containers_stats_interval_ms, Cfg,
                         ?DEFAULT_INTERVAL_MS),
    max(?MIN_INTERVAL_MS, Requested).

-spec schedule_next(pos_integer()) -> reference().
schedule_next(Interval) ->
    erlang:send_after(Interval, self(), poll).

-spec do_poll() -> {ok, emitted | skipped | {error, term()}}.
do_poll() ->
    case catch erlkoenig_cgroup:read_containers_stats() of
        {ok, Stats} when is_map(Stats) ->
            erlkoenig_events:notify({containers_stats, payload(Stats)}),
            {ok, emitted};
        {error, Reason} ->
            logger:debug("cgroup_stats: containers stats unavailable: ~p",
                         [Reason]),
            {ok, {error, Reason}};
        _Other ->
            {ok, skipped}
    end.

-spec with_memory_headroom(map(), non_neg_integer(), non_neg_integer() | max) -> map().
with_memory_headroom(Payload, _Current, max) ->
    Payload;
with_memory_headroom(Payload, Current, Max) when is_integer(Max), Max > 0 ->
    Available = max(0, Max - Current),
    Payload#{
        memory_available => Available,
        memory_pct => percent(Current, Max)
    };
with_memory_headroom(Payload, _Current, _Max) ->
    Payload.

-spec with_pids_headroom(map(), non_neg_integer(), non_neg_integer() | max) -> map().
with_pids_headroom(Payload, _Current, max) ->
    Payload;
with_pids_headroom(Payload, Current, Max) when is_integer(Max), Max > 0 ->
    Available = max(0, Max - Current),
    Payload#{
        pids_available => Available,
        pids_pct => percent(Current, Max)
    };
with_pids_headroom(Payload, _Current, _Max) ->
    Payload.

-spec percent(non_neg_integer(), pos_integer()) -> float().
percent(Current, Max) ->
    (Current * 100.0) / Max.
