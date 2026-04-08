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

-module(erlkoenig_threat_actor).
-moduledoc """
Per-IP threat detection state machine.

One process per suspicious source IP. Detects floods, port scans,
slow scans, and honeypot probes. Sends ban/unban intentions to
erlkoenig_threat_mesh — never speaks to the kernel directly.

States: observing → suspicious → banned → probation → (stop)

Process lifecycle:
- Started on first suspicious event for an IP
- Dies on idle timeout (no traffic) or after probation
- Process death = clean state removal (ETS entry deleted in terminate)
""".

-behaviour(gen_statem).

-export([start_link/2, connection/2]).
-export([init/1, callback_mode/0, terminate/3]).
-export([observing/3, suspicious/3, banned/3, probation/3]).

%% Idle timeout: 5 minutes without events → process dies
-define(IDLE_TIMEOUT_MS, 300_000).
%% Probation: 2 minutes after unban
-define(PROBATION_MS, 120_000).

-record(data, {
    ip :: binary(),
    config :: map(),
    %% Detection state
    ports_seen :: sets:set(inet:port_number()),
    conn_timestamps :: [integer()],  %% recent connection timestamps (seconds)
    first_seen :: integer(),
    last_seen :: integer(),
    %% Escalation
    ban_count :: non_neg_integer(),
    %% ETS table name for cleanup in terminate
    registry :: atom()
}).

%% ===================================================================
%% Public API
%% ===================================================================

-doc """
Start a threat actor for the given IP.

Config must contain detection thresholds:
  flood_max, flood_window, scan_max, scan_window,
  slow_max, slow_window, ban_duration, honeypot_ban_duration,
  honeypot_ports (sets:set())
""".
-spec start_link(binary(), map()) -> gen_statem:start_ret().
start_link(IP, Config) ->
    gen_statem:start_link(?MODULE, {IP, Config}, []).

-doc "Report a new connection from this IP to DstPort.".
-spec connection(pid(), inet:port_number()) -> ok.
connection(Pid, DstPort) ->
    gen_statem:cast(Pid, {connection, DstPort}).

%% ===================================================================
%% gen_statem callbacks
%% ===================================================================

callback_mode() -> state_functions.

init({IP, Config}) ->
    Now = erlang:system_time(second),
    Registry = maps:get(registry, Config, erlkoenig_threat_actor_registry),
    {ok, observing, #data{
        ip = IP,
        config = Config,
        ports_seen = sets:new([{version, 2}]),
        conn_timestamps = [],
        first_seen = Now,
        last_seen = Now,
        ban_count = 0,
        registry = Registry
    }, [{state_timeout, ?IDLE_TIMEOUT_MS, idle_expire}]}.

terminate(_Reason, _State, #data{ip = IP, registry = Reg}) ->
    try ets:delete(Reg, IP)
    catch error:badarg -> ok  %% table gone (supervisor crash)
    end,
    ok.

%% ===================================================================
%% State: observing
%% ===================================================================

observing(cast, {connection, DstPort}, Data) ->
    Data2 = record_event(DstPort, Data),
    case check_triggers(DstPort, Data2) of
        {ban, Reason, Duration} ->
            do_ban(Reason, Duration, Data2);
        suspect ->
            broadcast({ct_guard_suspect, #{ip => Data2#data.ip,
                ports => sets:to_list(Data2#data.ports_seen)}}),
            {next_state, suspicious, Data2,
             [{state_timeout, ?IDLE_TIMEOUT_MS, idle_expire}]};
        clear ->
            {keep_state, Data2,
             [{state_timeout, ?IDLE_TIMEOUT_MS, idle_expire}]}
    end;

observing(state_timeout, idle_expire, _Data) ->
    {stop, normal}.

%% ===================================================================
%% State: suspicious (3+ ports seen, not yet banned)
%% ===================================================================

suspicious(cast, {connection, DstPort}, Data) ->
    Data2 = record_event(DstPort, Data),
    case check_triggers(DstPort, Data2) of
        {ban, Reason, Duration} ->
            do_ban(Reason, Duration, Data2);
        _ ->
            {keep_state, Data2,
             [{state_timeout, ?IDLE_TIMEOUT_MS, idle_expire}]}
    end;

suspicious(state_timeout, idle_expire, _Data) ->
    {stop, normal}.

%% ===================================================================
%% State: banned (waiting for timer to fire)
%% ===================================================================

banned(cast, {connection, _DstPort}, Data) ->
    %% Already banned, ignore new connections
    {keep_state, Data};

banned(state_timeout, unban, #data{ip = IP} = Data) ->
    erlkoenig_threat_mesh:local_unban(IP),
    {next_state, probation, Data,
     [{state_timeout, ?PROBATION_MS, probation_expire}]}.

%% ===================================================================
%% State: probation (recently unbanned, watching for recidivism)
%% ===================================================================

probation(cast, {connection, DstPort}, Data) ->
    %% Repeat offender: back to observing with incremented ban_count
    Data2 = Data#data{
        ban_count = Data#data.ban_count + 1,
        ports_seen = sets:from_list([DstPort], [{version, 2}]),
        conn_timestamps = [erlang:system_time(second)],
        last_seen = erlang:system_time(second)
    },
    {next_state, observing, Data2,
     [{state_timeout, ?IDLE_TIMEOUT_MS, idle_expire}]};

probation(state_timeout, probation_expire, _Data) ->
    {stop, normal}.

%% ===================================================================
%% Internal
%% ===================================================================

record_event(DstPort, #data{conn_timestamps = Ts, ports_seen = Ports} = Data) ->
    Now = erlang:system_time(second),
    %% Keep only timestamps within the largest window (slow_scan)
    SlowWindow = maps:get(slow_window, Data#data.config, 3600),
    Cutoff = Now - SlowWindow,
    RecentTs = [T || T <- [Now | Ts], T >= Cutoff],
    Data#data{
        ports_seen = sets:add_element(DstPort, Ports),
        conn_timestamps = RecentTs,
        last_seen = Now
    }.

check_triggers(DstPort, #data{config = Config} = Data) ->
    %% Check in order: honeypot (instant) → flood → scan → slow_scan → suspect
    HoneypotPorts = maps:get(honeypot_ports, Config, sets:new()),
    case sets:is_element(DstPort, HoneypotPorts) of
        true ->
            HpDuration = maps:get(honeypot_ban_duration, Config, 86400),
            {ban, honeypot, HpDuration};
        false ->
            check_flood(Data)
    end.

check_flood(#data{conn_timestamps = Ts, config = Config} = Data) ->
    FloodMax = maps:get(flood_max, Config, 50),
    FloodWindow = maps:get(flood_window, Config, 10),
    Now = erlang:system_time(second),
    Cutoff = Now - FloodWindow,
    Count = length([T || T <- Ts, T >= Cutoff]),
    case Count >= FloodMax of
        true ->
            BaseDuration = maps:get(ban_duration, Config, 3600),
            {ban, conn_flood, escalate(BaseDuration, Data)};
        false ->
            check_scan(Data)
    end.

check_scan(#data{conn_timestamps = Ts, ports_seen = Ports, config = Config} = Data) ->
    ScanMax = maps:get(scan_max, Config, 20),
    ScanWindow = maps:get(scan_window, Config, 60),
    Now = erlang:system_time(second),
    Cutoff = Now - ScanWindow,
    %% Only count ports seen within the scan window
    HasRecentActivity = length([T || T <- Ts, T >= Cutoff]) > 0,
    PortCount = sets:size(Ports),
    case HasRecentActivity andalso PortCount >= ScanMax of
        true ->
            BaseDuration = maps:get(ban_duration, Config, 3600),
            {ban, port_scan, escalate(BaseDuration, Data)};
        false ->
            check_slow_scan(Data)
    end.

check_slow_scan(#data{ports_seen = Ports, first_seen = FirstSeen,
                       config = Config} = Data) ->
    SlowMax = maps:get(slow_max, Config, 5),
    SlowWindow = maps:get(slow_window, Config, 3600),
    Now = erlang:system_time(second),
    Elapsed = Now - FirstSeen,
    PortCount = sets:size(Ports),
    case Elapsed =< SlowWindow andalso PortCount >= SlowMax of
        true ->
            BaseDuration = maps:get(ban_duration, Config, 3600),
            {ban, slow_scan, escalate(BaseDuration, Data)};
        false when Elapsed > SlowWindow ->
            %% Window expired, this would be handled by idle timeout
            check_suspect(Data);
        false ->
            check_suspect(Data)
    end.

check_suspect(#data{ports_seen = Ports, config = Config}) ->
    SuspectAfter = maps:get(suspect_after, Config, 3),
    case sets:size(Ports) >= SuspectAfter of
        true -> suspect;
        false -> clear
    end.

escalate(_BaseDuration, #data{ban_count = BanCount, config = Config}) ->
    %% Escalation list from DSL config: [3600, 21600, 86400, 604800]
    %% Each entry is the absolute ban duration for that ban number.
    Escalation = maps:get(escalation, Config, [3600, 21600, 86400, 604800]),
    Idx = min(BanCount + 1, length(Escalation)),
    lists:nth(Idx, Escalation).

do_ban(Reason, DurationSec, #data{ip = IP} = Data) ->
    BanUntil = os:system_time(millisecond) + (DurationSec * 1000),
    erlkoenig_threat_mesh:local_ban(IP, BanUntil, Reason),
    broadcast({ct_guard_ban, #{
        ip => IP,
        reason => Reason,
        duration => DurationSec,
        ban_count => Data#data.ban_count
    }}),
    {next_state, banned, Data,
     [{state_timeout, DurationSec * 1000, unban}]}.

broadcast(Msg) ->
    try
        Members = pg:get_members(erlkoenig_nft, ct_guard_events),
        _ = [Pid ! Msg || Pid <- Members],
        ok
    catch _:_ -> ok
    end.
