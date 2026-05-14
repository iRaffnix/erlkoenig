%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_observe).
-moduledoc """
Observability helpers extracted from `erlkoenig_ct'.

Everything the state machine does that is *only* for reporting:

  * Stats polling — `start_stats_timers/1', `cancel_stats_timers/1',
    `poll_and_publish_stats/2', `publish_each_metric/5',
    `round_2/1'.
  * Log publisher wiring — `maybe_start_log_publisher/1',
    `maybe_stop_log_publisher/1', `forward_output/3'.
  * Stopped-event emission — `notify_stopped/1'.
  * Stats-into-info projection — `maybe_add_stats/3'.

`build_info/2' stayed in `erlkoenig_ct' deliberately — it's the
canonical state-machine-to-public-map projection and every
`get_info' clause calls it from the callback itself. Pulling it
out buys less than it costs.

Side effects: `erlkoenig_events:notify/1', `erlang:send_after/3',
`erlang:cancel_timer/1', `erlkoenig_cgroup' reads, log-publisher
start/stop, `gen_server:cast/2' into the publisher. Pure helpers
are still pure (`round_2/1', `start_stats_timers/1').
""".

-include("erlkoenig_ct_state.hrl").

-export([
    %% Stats polling
    start_stats_timers/1,
    cancel_stats_timers/1,
    poll_and_publish_stats/2,
    publish_each_metric/5,
    round_2/1,
    %% Log publisher
    maybe_start_log_publisher/1,
    maybe_stop_log_publisher/1,
    forward_output/3,
    %% Event notifications
    notify_stopped/1,
    should_notify_oom/3,
    %% Public-map projection helpers
    maybe_add_stats/3
]).

%% -- Stats timers (SPEC-EK-007) -----------------------------------

-spec start_stats_timers([map()]) -> [reference()].
start_stats_timers(PublishBlocks) ->
    lists:map(fun(#{interval := Interval, metrics := Metrics}) ->
        erlang:send_after(Interval, self(), {poll_stats, Interval, Metrics})
    end, PublishBlocks).

-spec cancel_stats_timers([reference()]) -> ok.
cancel_stats_timers(Timers) ->
    lists:foreach(fun(Ref) -> erlang:cancel_timer(Ref) end, Timers),
    ok.

-spec poll_and_publish_stats([atom()], #ct_data{}) -> #ct_data{}.
poll_and_publish_stats(Metrics, #ct_data{id = Id, name = Name} = Data) ->
    case erlkoenig_cgroup:read_metrics(Id, Metrics) of
        {ok, Raw} ->
            publish_each_metric(Metrics, Raw, Id, Name, Data);
        {error, _} ->
            Data
    end.

-spec publish_each_metric([atom()], map(), binary(),
                          binary() | undefined, #ct_data{}) ->
    #ct_data{}.
publish_each_metric([], _Raw, _Id, _Name, Data) ->
    Data;
publish_each_metric([memory | Rest], Raw, Id, Name, Data) ->
    Current = maps:get(memory_bytes, Raw, 0),
    Peak = maps:get(memory_peak, Raw, 0),
    Max = maps:get(memory_max, Raw, max),
    Swap = maps:get(memory_swap, Raw, 0),
    Pct = case Max of
        max -> 0.0;
        0   -> 0.0;
        M   -> Current / M * 100
    end,
    erlkoenig_events:notify({container_stats, Id, Name, memory, #{
        current => Current, peak => Peak, max => Max,
        pct => round_2(Pct), swap => Swap
    }}),
    publish_each_metric(Rest, Raw, Id, Name, Data);
publish_each_metric([cpu | Rest], Raw, Id, Name, Data) ->
    Usec = maps:get(cpu_usec, Raw, 0),
    Throttled = maps:get(cpu_throttled_usec, Raw, 0),
    NrThrottled = maps:get(cpu_nr_throttled, Raw, 0),
    DeltaUsec = case Data#ct_data.last_cpu_usec of
        undefined -> 0;
        Last      -> Usec - Last
    end,
    erlkoenig_events:notify({container_stats, Id, Name, cpu, #{
        usec => Usec, delta_usec => DeltaUsec,
        throttled_usec => Throttled, nr_throttled => NrThrottled
    }}),
    publish_each_metric(Rest, Raw, Id, Name, Data#ct_data{last_cpu_usec = Usec});
publish_each_metric([pids | Rest], Raw, Id, Name, Data) ->
    Current = maps:get(pids_current, Raw, 0),
    Max = maps:get(pids_max, Raw, max),
    erlkoenig_events:notify({container_stats, Id, Name, pids, #{
        current => Current, max => Max
    }}),
    publish_each_metric(Rest, Raw, Id, Name, Data);
publish_each_metric([pressure | Rest], Raw, Id, Name, Data) ->
    CpuP = maps:get(cpu_pressure, Raw, #{}),
    MemP = maps:get(memory_pressure, Raw, #{}),
    IoP = maps:get(io_pressure, Raw, #{}),
    erlkoenig_events:notify({container_stats, Id, Name, pressure, #{
        cpu_some_avg10 => maps:get(avg10, CpuP, 0.0),
        cpu_some_avg60 => maps:get(avg60, CpuP, 0.0),
        memory_some_avg10 => maps:get(avg10, MemP, 0.0),
        io_some_avg10 => maps:get(avg10, IoP, 0.0)
    }}),
    publish_each_metric(Rest, Raw, Id, Name, Data);
publish_each_metric([oom_events | Rest], Raw, Id, Name, Data) ->
    Events = maps:get(memory_events, Raw, #{}),
    erlkoenig_events:notify({container_stats, Id, Name, oom, #{
        kills => maps:get(oom_kill, Events, 0),
        events => maps:get(oom, Events, 0),
        high => maps:get(high, Events, 0),
        max => maps:get(max, Events, 0)
    }}),
    publish_each_metric(Rest, Raw, Id, Name, Data);
publish_each_metric([_ | Rest], Raw, Id, Name, Data) ->
    publish_each_metric(Rest, Raw, Id, Name, Data).

-spec round_2(float()) -> float().
round_2(F) ->
    round(F * 100) / 100.

%% -- Log publisher (SPEC-EK-011) ----------------------------------

-spec maybe_start_log_publisher(#ct_data{}) ->
    {pid(), atomics:atomics_ref()} | undefined.
maybe_start_log_publisher(#ct_data{stream = undefined}) -> undefined;
maybe_start_log_publisher(#ct_data{stream = #{channels := Channels} = StreamCfg,
                                    id = Id, name = Name}) ->
    RetentionDays = maps:get(retention_days, StreamCfg, 7),
    InFlight = atomics:new(1, []),
    case erlkoenig_log_publisher:start_link(Id, Name, Channels, RetentionDays, InFlight) of
        {ok, Pid} ->
            {Pid, InFlight};
        {error, Reason} ->
            logger:warning("container ~s: log publisher failed: ~p", [Name, Reason]),
            undefined
    end.

-spec maybe_stop_log_publisher({pid(), atomics:atomics_ref()} | undefined) -> ok.
maybe_stop_log_publisher(undefined) -> ok;
maybe_stop_log_publisher({Pid, _InFlight}) ->
    try erlkoenig_log_publisher:stop(Pid)
    catch _:_ -> ok
    end.

%% -- Output forwarding --------------------------------------------

-define(LOG_HIGH_WATERMARK, 2000).

-spec forward_output(stdout | stderr, binary(), #ct_data{}) -> ok.
forward_output(Stream, Chunk, #ct_data{output = OutputPid,
                                        log_publisher = LogPub} = Data) ->
    %% 1. Attached pid (interactive consumer)
    _ = case OutputPid of
        undefined -> ok;
        Pid ->
            Tag = case Stream of
                      stdout -> container_stdout;
                      stderr -> container_stderr
                  end,
            Pid ! {Tag, self(), Data#ct_data.id, Chunk}
    end,
    %% 2. Log publisher (stream to RabbitMQ, if configured)
    case LogPub of
        undefined -> ok;
        {Pub, InFlight} ->
            case atomics:get(InFlight, 1) >= ?LOG_HIGH_WATERMARK of
                true ->
                    ok; %% drop — admission control before message alloc
                false ->
                    atomics:add(InFlight, 1, 1),
                    gen_server:cast(Pub, {log, Stream, Chunk})
            end
    end,
    ok.

%% -- Event notifications ------------------------------------------

-spec notify_stopped(#ct_data{}) -> ok.
notify_stopped(#ct_data{id = Id, name = Name, exit_info = ExitInfo,
                        user_stopped = UserStopped}) ->
    erlkoenig_events:notify({container_stopped, Id, Name, ExitInfo}),
    %% Detect OOM-Kill via cgroup memory.events (authoritative).
    %% Fallback to signal heuristic for non-operator stops.
    %%
    %% ExitInfo can be `undefined' when a container is stopped via
    %% the recovering/disconnected → stopped path (kill_os_pid,
    %% user_stopped=true). The previous `maps:get(term_signal,
    %% ExitInfo, 0)' call crashed badmap on that path and took down
    %% the gen_statem instead of just emitting container_stopped.
    case should_notify_oom(UserStopped, ExitInfo,
                           erlkoenig_cgroup:was_oom_killed(Id)) of
        true  -> erlkoenig_events:notify({container_oom, Id, Name});
        false -> ok
    end.

-spec should_notify_oom(boolean(), term(), boolean()) -> boolean().
should_notify_oom(true, _ExitInfo, _CgroupOOM) ->
    %% Operator-initiated stop may escalate to SIGKILL after the grace
    %% timeout. That is not an OOM and must not page as one.
    false;
should_notify_oom(false, _ExitInfo, true) ->
    true;
should_notify_oom(false, ExitInfo, false) when is_map(ExitInfo) ->
    maps:get(term_signal, ExitInfo, 0) =:= 9;
should_notify_oom(false, _ExitInfo, false) ->
    false.

%% -- Public-map projection helpers --------------------------------

-spec maybe_add_stats(atom(), binary(), map()) -> map().
maybe_add_stats(running, Id, Info) ->
    case erlkoenig_cgroup:read_stats(Id) of
        {ok, Stats} when map_size(Stats) > 0 -> Info#{stats => Stats};
        _                                     -> Info
    end;
maybe_add_stats(_State, _Id, Info) ->
    Info.
