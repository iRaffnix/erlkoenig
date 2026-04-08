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

-module(erlkoenig_nft_ct_guard).
-moduledoc """
Automatic threat detection and response using conntrack events.

Subscribes to the ct_events pg group and watches for malicious
connection patterns. When a threshold is exceeded, the offending
source IP is automatically banned with an expiring timeout.

Detection rules:

  1. Connection flood: More than N new connections from a single
     source IP within T seconds. Catches SYN floods and HTTP floods.

  2. Port scan: Connections to more than M distinct destination
     ports from a single source IP within T seconds.

Bans are temporary and auto-expire. The guard maintains a sliding
window of recent connections per source IP and cleans up expired
entries periodically.

Configuration (in firewall.term):

    ct_guard => #{
        conn_flood => {50, 10},     %% 50 new conns in 10s -> ban
        port_scan  => {20, 60},     %% 20 distinct ports in 60s -> ban
        ban_duration => 3600,       %% ban lasts 1 hour (seconds)
        whitelist => [              %% never ban these
            {127, 0, 0, 1},
            {10, 0, 0, 1}
        ],
        cleanup_interval => 30000   %% clean expired entries every 30s
    }

Usage:

    erlkoenig_nft_ct_guard:start_link(Config).
    erlkoenig_nft_ct_guard:stats().
    erlkoenig_nft_ct_guard:banned().
""".

-behaviour(gen_server).

-export([start_link/1, stop/1]).
-export([stats/0, banned/0, reconfigure/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% --- Defaults ---

%% 50 conns in 10s
-define(DEFAULT_CONN_FLOOD, {50, 10}).
%% 20 ports in 60s
-define(DEFAULT_PORT_SCAN, {20, 60}).
%% 5 distinct ports in 3600s (1 hour)
-define(DEFAULT_SLOW_SCAN, {5, 3600}).
%% 1 hour
-define(DEFAULT_BAN_DURATION, 3600).
%% 24 hours for honeypot bans
-define(DEFAULT_HONEYPOT_BAN_DURATION, 86400).
%% 30 seconds
-define(DEFAULT_CLEANUP_INTERVAL, 30000).
-define(DEFAULT_WHITELIST, []).
%% Ports that no legitimate user would connect to.
%% Any single connection = instant ban.
-define(DEFAULT_HONEYPOT_PORTS, [
    21, 22, 23, 445, 1433, 1521, 3306, 3389, 5900, 6379, 8080, 8888, 9200, 27017
]).
%% Repeat offender: escalation multipliers per ban count
-define(ESCALATION, [1, 6, 24, 168]).

%% ETS tables

%% {SrcIP, Timestamp, DstPort}
-define(GUARD_CONNS, erlkoenig_nft_ct_guard_conns).
%% {SrcIP, BannedAt, ExpiresAt, Reason}
-define(GUARD_BANS, erlkoenig_nft_ct_guard_bans).
%% Per-IP threat actor registry: {SrcIP, Pid | starting}
-define(ACTOR_REGISTRY, erlkoenig_threat_actor_registry).

%% --- Public API ---

-doc "Start the guard with configuration from firewall.term ct_guard section.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Config) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

-doc "Stop the guard.".
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

-doc "Get guard operational statistics.".
-spec stats() -> map().
stats() ->
    gen_server:call(?MODULE, stats).

-doc "List all currently banned IPs with ban details.".
-spec banned() -> [map()].
banned() ->
    gen_server:call(?MODULE, banned).

-doc "Reconfigure thresholds and whitelist without losing active bans/stats.".
-spec reconfigure(map()) -> ok.
reconfigure(Config) ->
    gen_server:call(?MODULE, {reconfigure, Config}).

%% --- gen_server callbacks ---

init(Config) ->
    proc_lib:set_label(erlkoenig_nft_ct_guard),
    %% Parse config
    {FloodMax, FloodWindow} = maps:get(conn_flood, Config, ?DEFAULT_CONN_FLOOD),
    {ScanMax, ScanWindow} = maps:get(port_scan, Config, ?DEFAULT_PORT_SCAN),
    {SlowMax, SlowWindow} = maps:get(slow_scan, Config, ?DEFAULT_SLOW_SCAN),
    BanDuration = maps:get(ban_duration, Config, ?DEFAULT_BAN_DURATION),
    HoneypotBanDuration = maps:get(honeypot_ban_duration, Config, ?DEFAULT_HONEYPOT_BAN_DURATION),
    CleanupMs = maps:get(cleanup_interval, Config, ?DEFAULT_CLEANUP_INTERVAL),
    Whitelist = normalize_whitelist(maps:get(whitelist, Config, ?DEFAULT_WHITELIST)),
    HoneypotPorts = sets:from_list(maps:get(honeypot_ports, Config, ?DEFAULT_HONEYPOT_PORTS)),
    Escalation = maps:get(escalation, Config, [3600, 21600, 86400, 604800]),

    %% Create ETS tables (defensive: handle restart race where table still exists)
    %% Conn tracking: ordered_set for efficient time-range queries
    _ = ensure_ets(?GUARD_CONNS, [named_table, ordered_set, public]),
    %% Ban tracking: set keyed by IP
    _ = ensure_ets(?GUARD_BANS, [named_table, set, public]),
    %% Threat actor registry: IP → Pid (owned by ct_guard, not by threat_sup)
    _ = ensure_ets(?ACTOR_REGISTRY, [named_table, set, public, {read_concurrency, true}]),

    %% Subscribe to conntrack events
    pg:join(erlkoenig_nft, ct_events, self()),

    %% Start cleanup timer
    erlang:send_after(CleanupMs, self(), cleanup),

    %% Start stats broadcast timer (every 5s)
    erlang:send_after(5000, self(), broadcast_stats),

    State = #{
        flood_max => FloodMax,
        flood_window => FloodWindow,
        scan_max => ScanMax,
        scan_window => ScanWindow,
        slow_max => SlowMax,
        slow_window => SlowWindow,
        ban_duration => BanDuration,
        honeypot_ban_duration => HoneypotBanDuration,
        honeypot_ports => HoneypotPorts,
        cleanup_ms => CleanupMs,
        whitelist => Whitelist,
        escalation => Escalation,
        %% Stats (detection counts updated by actors via ct_guard_events broadcast)
        events_seen => 0,
        floods_detected => 0,
        scans_detected => 0,
        slow_scans_detected => 0,
        honeypots_triggered => 0,
        bans_issued => 0,
        bans_expired => 0
    },

    logger:notice(
        "[ct_guard] Started: flood=~p/~ps, scan=~p/~ps, slow=~p/~ps, honeypot=~p ports, ban=~ps",
        [FloodMax, FloodWindow, ScanMax, ScanWindow, SlowMax, SlowWindow,
         sets:size(HoneypotPorts), BanDuration]
    ),

    {ok, State}.

handle_call(stats, _From, State) ->
    #{
        events_seen := Seen,
        floods_detected := Floods,
        scans_detected := Scans,
        slow_scans_detected := SlowScans,
        honeypots_triggered := Honeypots,
        bans_issued := Issued,
        bans_expired := Expired,
        flood_max := FM,
        flood_window := FW,
        scan_max := SM,
        scan_window := SW,
        slow_max := SlM,
        slow_window := SlW,
        ban_duration := BD,
        honeypot_ban_duration := HBD,
        honeypot_ports := HP
    } = State,
    %% Threat actor stats
    ActorCount = try ets:info(?ACTOR_REGISTRY, size) catch error:badarg -> 0 end,
    MeshBans = try map_size(erlkoenig_threat_mesh:active_bans())
               catch exit:{noproc, _} -> 0 end,
    Stats = #{
        events_seen => Seen,
        floods_detected => Floods,
        scans_detected => Scans,
        slow_scans_detected => SlowScans,
        honeypots_triggered => Honeypots,
        bans_issued => Issued,
        bans_expired => Expired,
        active_bans => MeshBans,
        active_actors => ActorCount,
        tracked_events => ets:info(?GUARD_CONNS, size),
        config => #{
            conn_flood => {FM, FW},
            port_scan => {SM, SW},
            slow_scan => {SlM, SlW},
            ban_duration => BD,
            honeypot_ban_duration => HBD,
            honeypot_ports => sets:size(HP)
        }
    },
    {reply, Stats, State};
handle_call(banned, _From, State) ->
    Now = os:system_time(millisecond),
    ActiveBans = try erlkoenig_threat_mesh:active_bans()
                 catch exit:{noproc, _} -> #{}
                 end,
    Bans = maps:fold(fun(IP, Sources, Acc) ->
        EffExpiry = lists:max(maps:values(Sources)),
        RemainingMs = max(0, EffExpiry - Now),
        case RemainingMs > 0 of
            true ->
                [#{ip => erlkoenig_nft_ip:format(IP),
                   ip_raw => IP,
                   sources => maps:keys(Sources),
                   remaining_seconds => RemainingMs div 1000} | Acc];
            false ->
                Acc
        end
    end, [], ActiveBans),
    {reply, Bans, State};
handle_call({reconfigure, Config}, _From, State) ->
    {FloodMax, FloodWindow} = maps:get(conn_flood, Config, {
        maps:get(flood_max, State), maps:get(flood_window, State)
    }),
    {ScanMax, ScanWindow} = maps:get(port_scan, Config, {
        maps:get(scan_max, State), maps:get(scan_window, State)
    }),
    BanDuration = maps:get(ban_duration, Config, maps:get(ban_duration, State)),
    Whitelist =
        case maps:find(whitelist, Config) of
            {ok, WL} -> normalize_whitelist(WL);
            error -> maps:get(whitelist, State)
        end,
    State2 = State#{
        flood_max := FloodMax,
        flood_window := FloodWindow,
        scan_max := ScanMax,
        scan_window := ScanWindow,
        ban_duration := BanDuration,
        whitelist := Whitelist
    },
    logger:notice(
        "[ct_guard] Reconfigured: flood=~p/~ps, scan=~p/~ps, ban=~ps",
        [FloodMax, FloodWindow, ScanMax, ScanWindow, BanDuration]
    ),
    {reply, ok, State2};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% --- Conntrack event ---
handle_info({ct_new, #{src := SrcIP} = Event}, State) ->
    #{events_seen := Seen, whitelist := WL} = State,
    State2 = State#{events_seen := Seen + 1},

    case is_whitelisted(SrcIP, WL) of
        true ->
            {noreply, State2};
        false ->
            DstPort = maps:get(dport, Event, 0),
            Now = erlang:system_time(second),

            %% Record connection event (kept for stats/cleanup)
            Key = {SrcIP, Now, erlang:unique_integer([positive])},
            ets:insert(?GUARD_CONNS, {Key, DstPort}),

            %% Delegate detection to per-IP threat actor
            case ensure_actor(SrcIP, State2) of
                {ok, Pid} ->
                    erlkoenig_threat_actor:connection(Pid, DstPort);
                drop ->
                    ok
            end,
            {noreply, State2}
    end;
handle_info({ct_destroy, _}, State) ->
    {noreply, State};
handle_info({ct_alert, _}, State) ->
    {noreply, State};
%% --- Periodic stats broadcast (every 5s) ---
handle_info(broadcast_stats, #{events_seen := Seen} = State) ->
    ActorCount = try ets:info(?ACTOR_REGISTRY, size) catch error:badarg -> 0 end,
    MeshBans = try map_size(erlkoenig_threat_mesh:active_bans())
               catch exit:{noproc, _} -> 0 end,
    StatsEvent = {guard_stats, #{
        actors => ActorCount,
        bans => MeshBans,
        events_seen => Seen,
        tracked_events => ets:info(?GUARD_CONNS, size)
    }},
    try
        Members = pg:get_members(erlkoenig_nft, ct_guard_events),
        _ = [Pid ! StatsEvent || Pid <- Members],
        ok
    catch _:_ -> ok
    end,
    erlang:send_after(5000, self(), broadcast_stats),
    {noreply, State};
%% --- Cleanup timer ---
handle_info(cleanup, #{cleanup_ms := Ms} = State) ->
    State2 = do_cleanup(State),
    erlang:send_after(Ms, self(), cleanup),
    {noreply, State2};
%% Unban timers are now managed by threat_mesh, not ct_guard.
%% Legacy {unban, _} messages are ignored.
handle_info({unban, _SrcIP}, State) ->
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    pg:leave(erlkoenig_nft, ct_events, self()),
    try ets:delete(?GUARD_CONNS) catch error:badarg -> ok end,
    %% GUARD_BANS kept for backward compat but no longer written by ct_guard.
    %% ACTOR_REGISTRY survives ct_guard restart (owned by this process).
    ok.

%% ===================================================================
%% Detection is now handled by erlkoenig_threat_actor (per-IP gen_statem).
%% Ban execution goes through erlkoenig_threat_mesh (single source of truth).
%% ct_guard's role is: event routing + stats + cleanup.
%% ===================================================================

%% ===================================================================
%% Cleanup
%% ===================================================================

do_cleanup(
    #{
        flood_window := FW,
        scan_window := SW,
        slow_window := SlW
    } = State
) ->
    Now = erlang:system_time(second),

    %% Remove connection events older than the largest window
    MaxWindow = max(max(FW, SW), SlW),
    Cutoff = Now - MaxWindow,
    ExpiredConns = delete_before(ets:first(?GUARD_CONNS), Cutoff, 0),

    case ExpiredConns > 0 of
        true ->
            logger:debug("[ct_guard] Cleanup: ~p events expired", [ExpiredConns]);
        false ->
            ok
    end,

    %% Bans are managed by threat_mesh, not ct_guard.
    State.

delete_before('$end_of_table', _, Count) ->
    Count;
delete_before({_IP, Ts, _} = Key, Cutoff, Count) when Ts < Cutoff ->
    Next = ets:next(?GUARD_CONNS, Key),
    ets:delete(?GUARD_CONNS, Key),
    delete_before(Next, Cutoff, Count + 1);
delete_before(_, _, Count) ->
    Count.

%% ===================================================================
%% Whitelist
%% ===================================================================

normalize_whitelist(List) ->
    lists:filtermap(
        fun(Entry) ->
            case erlkoenig_nft_ip:normalize(Entry) of
                {ok, Bin} -> {true, Bin};
                {error, _} -> false
            end
        end,
        List
    ).

is_whitelisted(SrcIP, Whitelist) ->
    lists:member(SrcIP, Whitelist).

%% ===================================================================
%% Helpers
%% ===================================================================

%% broadcast/1 removed — detection events are now broadcast by
%% erlkoenig_threat_actor and erlkoenig_threat_mesh directly.

%% Race-free actor creation. ets:insert_new is atomic — only one caller
%% wins. The winner starts the actor and replaces `starting` with the
%% real pid. Losers retry (max 2 times).
-spec ensure_actor(binary(), map()) -> {ok, pid()} | drop.
ensure_actor(SrcIP, Config) ->
    ensure_actor(SrcIP, Config, 0).

ensure_actor(_SrcIP, _Config, Retries) when Retries > 2 ->
    drop;
ensure_actor(SrcIP, Config, Retries) ->
    case ets:lookup(?ACTOR_REGISTRY, SrcIP) of
        [{_, Pid}] when is_pid(Pid) ->
            case is_process_alive(Pid) of
                true -> {ok, Pid};
                false ->
                    ets:delete(?ACTOR_REGISTRY, SrcIP),
                    ensure_actor(SrcIP, Config, Retries + 1)
            end;
        [{_, starting}] ->
            timer:sleep(1),
            ensure_actor(SrcIP, Config, Retries + 1);
        [] ->
            case ets:insert_new(?ACTOR_REGISTRY, {SrcIP, starting}) of
                true ->
                    ActorConfig = build_actor_config(Config),
                    try
                        {ok, Pid} = erlkoenig_threat_sup:start_actor(SrcIP, ActorConfig),
                        ets:update_element(?ACTOR_REGISTRY, SrcIP, {2, Pid}),
                        {ok, Pid}
                    catch _:_ ->
                        ets:delete(?ACTOR_REGISTRY, SrcIP),
                        drop
                    end;
                false ->
                    ensure_actor(SrcIP, Config, Retries + 1)
            end
    end.

%% Build config map for threat actor from ct_guard state.
build_actor_config(State) ->
    #{flood_max := FM, flood_window := FW,
      scan_max := SM, scan_window := SW,
      slow_max := SlM, slow_window := SlW,
      ban_duration := BD, honeypot_ban_duration := HBD,
      honeypot_ports := HP} = State,
    Escalation = maps:get(escalation, State, [3600, 21600, 86400, 604800]),
    #{flood_max => FM, flood_window => FW,
      scan_max => SM, scan_window => SW,
      slow_max => SlM, slow_window => SlW,
      ban_duration => BD, honeypot_ban_duration => HBD,
      honeypot_ports => HP, escalation => Escalation}.

%% Defensive ETS creation: if the table already exists (restart race),
%% reuse it instead of crashing with badarg.
ensure_ets(Name, Opts) ->
    case ets:whereis(Name) of
        undefined -> ets:new(Name, Opts);
        _Tid -> Name
    end.
