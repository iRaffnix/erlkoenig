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

    %% Create ETS tables (defensive: handle restart race where table still exists)
    %% Conn tracking: ordered_set for efficient time-range queries
    _ = ensure_ets(?GUARD_CONNS, [named_table, ordered_set, public]),
    %% Ban tracking: set keyed by IP
    _ = ensure_ets(?GUARD_BANS, [named_table, set, public]),

    %% Subscribe to conntrack events
    pg:join(erlkoenig_nft, ct_events, self()),

    %% Start cleanup timer
    erlang:send_after(CleanupMs, self(), cleanup),

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
        %% Slow-scan tracker: #{SrcIP => #{ports => sets:set(), first_seen => Ts}}
        slow_tracker => #{},
        %% Ban history for repeat offender: #{SrcIP => BanCount}
        ban_history => #{},
        %% Stats
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
    Stats = #{
        events_seen => Seen,
        floods_detected => Floods,
        scans_detected => Scans,
        slow_scans_detected => SlowScans,
        honeypots_triggered => Honeypots,
        bans_issued => Issued,
        bans_expired => Expired,
        active_bans => ets:info(?GUARD_BANS, size),
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
    Now = erlang:system_time(second),
    Bans = ets:foldl(
        fun({IP, BannedAt, ExpiresAt, Reason}, Acc) ->
            Remaining = max(0, ExpiresAt - Now),
            [
                #{
                    ip => erlkoenig_nft_ip:format(IP),
                    ip_raw => IP,
                    reason => Reason,
                    banned_at => BannedAt,
                    expires_at => ExpiresAt,
                    remaining_seconds => Remaining
                }
                | Acc
            ]
        end,
        [],
        ?GUARD_BANS
    ),
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

    case is_whitelisted(SrcIP, WL) orelse is_banned(SrcIP) of
        true ->
            %% Skip whitelisted or already-banned IPs
            {noreply, State2};
        false ->
            DstPort = maps:get(dport, Event, 0),
            Now = erlang:system_time(second),

            %% Record connection event
            %% Key: {SrcIP, Timestamp, Unique} to allow multiple per second
            Key = {SrcIP, Now, erlang:unique_integer([positive])},
            ets:insert(?GUARD_CONNS, {Key, DstPort}),

            %% Check honeypot FIRST (instant ban, skip other checks)
            case check_honeypot(SrcIP, DstPort, State2) of
                {banned, State3} ->
                    {noreply, State3};
                {ok, State3} ->
                    %% Check other thresholds
                    State4 = check_flood(SrcIP, Now, State3),
                    State5 = check_port_scan(SrcIP, Now, State4),
                    State6 = check_slow_scan(SrcIP, DstPort, Now, State5),
                    {noreply, State6}
            end
    end;
handle_info({ct_destroy, _}, State) ->
    {noreply, State};
handle_info({ct_alert, _}, State) ->
    {noreply, State};
%% --- Cleanup timer ---
handle_info(cleanup, #{cleanup_ms := Ms} = State) ->
    State2 = do_cleanup(State),
    erlang:send_after(Ms, self(), cleanup),
    {noreply, State2};
%% --- Unban timer ---
handle_info({unban, SrcIP}, #{bans_expired := Exp} = State) ->
    case ets:lookup(?GUARD_BANS, SrcIP) of
        [{_, _, _, _}] ->
            ets:delete(?GUARD_BANS, SrcIP),
            _ = try_unban(SrcIP),
            broadcast({ct_guard_unban, #{ip => SrcIP}}),
            logger:notice("[ct_guard] Auto-unban ~s (expired)", [erlkoenig_nft_ip:format(SrcIP)]),
            {noreply, State#{bans_expired := Exp + 1}};
        [] ->
            {noreply, State}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    pg:leave(erlkoenig_nft, ct_events, self()),
    ets:delete(?GUARD_CONNS),
    ets:delete(?GUARD_BANS),
    ok.

%% ===================================================================
%% Detection: Connection Flood
%% ===================================================================

check_flood(SrcIP, Now, #{flood_max := Max, flood_window := Window} = State) ->
    Cutoff = Now - Window,
    Count = count_events(SrcIP, Cutoff),
    case Count >= Max of
        true ->
            ban_ip(SrcIP, conn_flood, State);
        false ->
            State
    end.

%% ===================================================================
%% Detection: Port Scan
%% ===================================================================

check_port_scan(SrcIP, Now, #{scan_max := Max, scan_window := Window} = State) ->
    Cutoff = Now - Window,
    Ports = distinct_ports(SrcIP, Cutoff),
    case length(Ports) >= Max of
        true ->
            ban_ip(SrcIP, port_scan, State);
        false ->
            State
    end.

%% ===================================================================
%% Detection: Honeypot Ports (instant ban on any connection)
%% ===================================================================

check_honeypot(SrcIP, DstPort, #{honeypot_ports := Ports,
                                  honeypot_ban_duration := Duration,
                                  honeypots_triggered := Count} = State) ->
    case sets:is_element(DstPort, Ports) of
        true ->
            logger:warning("[ct_guard] HONEYPOT ~s port=~p → instant ban ~ps",
                           [erlkoenig_nft_ip:format(SrcIP), DstPort, Duration]),
            State2 = ban_ip_with_duration(SrcIP, honeypot, Duration, State),
            broadcast({ct_guard_honeypot, #{ip => SrcIP, port => DstPort,
                                            duration => Duration}}),
            {banned, State2#{honeypots_triggered := Count + 1}};
        false ->
            {ok, State}
    end.

%% ===================================================================
%% Detection: Slow Scan (long window, low threshold)
%% ===================================================================

check_slow_scan(SrcIP, DstPort, Now,
                #{slow_max := Max, slow_window := Window,
                  slow_tracker := Tracker,
                  slow_scans_detected := Count} = State) ->
    Entry = maps:get(SrcIP, Tracker, #{ports => sets:new(), first_seen => Now}),
    #{ports := Ports, first_seen := FirstSeen} = Entry,
    case Now - FirstSeen > Window of
        true ->
            %% Window expired, reset
            NewEntry = #{ports => sets:from_list([DstPort]), first_seen => Now},
            State#{slow_tracker := maps:put(SrcIP, NewEntry, Tracker)};
        false ->
            NewPorts = sets:add_element(DstPort, Ports),
            case sets:size(NewPorts) >= Max of
                true ->
                    logger:warning("[ct_guard] SLOW_SCAN ~s ~p ports in ~ps",
                                   [erlkoenig_nft_ip:format(SrcIP),
                                    sets:size(NewPorts), Now - FirstSeen]),
                    broadcast({ct_guard_slow_scan, #{
                        ip => SrcIP,
                        ports => sets:to_list(NewPorts),
                        window => Now - FirstSeen
                    }}),
                    %% Ban with 2x normal duration
                    State2 = ban_ip(SrcIP, slow_scan, State),
                    State2#{slow_tracker := maps:remove(SrcIP, Tracker),
                            slow_scans_detected := Count + 1};
                false ->
                    NewEntry = Entry#{ports => NewPorts},
                    State#{slow_tracker := maps:put(SrcIP, NewEntry, Tracker)}
            end
    end.

%% ===================================================================
%% Ban Management
%% ===================================================================

ban_ip(SrcIP, Reason, #{ban_duration := BaseDuration} = State) ->
    %% Apply repeat-offender escalation
    Duration = escalate_duration(SrcIP, BaseDuration, State),
    ban_ip_with_duration(SrcIP, Reason, Duration, State).

ban_ip_with_duration(SrcIP, Reason, Duration,
                     #{bans_issued := Issued, ban_history := History} = State) ->
    case is_banned(SrcIP) of
        true ->
            State;
        false ->
            Now = erlang:system_time(second),
            ExpiresAt = Now + Duration,

            %% Record ban
            ets:insert(?GUARD_BANS, {SrcIP, Now, ExpiresAt, Reason}),

            %% Apply ban in firewall
            _ = try_ban(SrcIP),

            %% Schedule auto-unban
            erlang:send_after(Duration * 1000, self(), {unban, SrcIP}),

            %% Update ban history (repeat offender tracking)
            BanCount = maps:get(SrcIP, History, 0) + 1,
            History2 = maps:put(SrcIP, BanCount, History),

            %% Update stats
            StatKey =
                case Reason of
                    conn_flood -> floods_detected;
                    port_scan -> scans_detected;
                    slow_scan -> slow_scans_detected;
                    honeypot -> honeypots_triggered;
                    _ -> bans_issued
                end,
            DetectCount = maps:get(StatKey, State, 0),

            logger:warning(
                "[ct_guard] BANNED ~s reason=~p duration=~ps ban_count=~p",
                [erlkoenig_nft_ip:format(SrcIP), Reason, Duration, BanCount]
            ),

            %% Broadcast alert
            broadcast(
                {ct_guard_ban, #{
                    ip => SrcIP,
                    reason => Reason,
                    duration => Duration,
                    ban_count => BanCount,
                    expires_at => ExpiresAt
                }}
            ),

            State#{bans_issued := Issued + 1, StatKey := DetectCount + 1,
                   ban_history := History2}
    end.

%% Repeat offender: escalate ban duration based on ban count
escalate_duration(SrcIP, BaseDuration, #{ban_history := History}) ->
    BanCount = maps:get(SrcIP, History, 0),
    Multiplier = lists:nth(min(BanCount + 1, length(?ESCALATION)), ?ESCALATION),
    BaseDuration * Multiplier.

is_banned(SrcIP) ->
    ets:member(?GUARD_BANS, SrcIP).

try_ban(SrcIP) ->
    try
        erlkoenig_nft:ban(SrcIP)
    catch
        C:R ->
            logger:error(
                "[ct_guard] ban crashed for ~s: ~p:~p",
                [erlkoenig_nft_ip:format(SrcIP), C, R]
            )
    end.

try_unban(SrcIP) ->
    try
        erlkoenig_nft:unban(SrcIP)
    catch
        C:R ->
            logger:error(
                "[ct_guard] unban crashed for ~s: ~p:~p",
                [erlkoenig_nft_ip:format(SrcIP), C, R]
            )
    end.

%% ===================================================================
%% ETS Queries
%% ===================================================================

%% Count events from SrcIP since Cutoff
count_events(SrcIP, Cutoff) ->
    %% Keys are {SrcIP, Timestamp, Unique}, ordered
    %% We want all keys where element 1 = SrcIP, element 2 >= Cutoff
    StartKey = {SrcIP, Cutoff, 0},
    EndKey = {SrcIP, infinity, 0},
    count_range(ets:next(?GUARD_CONNS, StartKey), SrcIP, EndKey, 0).

count_range('$end_of_table', _, _, Count) ->
    Count;
count_range({IP, _, _} = Key, SrcIP, EndKey, Count) when IP =:= SrcIP ->
    count_range(ets:next(?GUARD_CONNS, Key), SrcIP, EndKey, Count + 1);
count_range(_, _, _, Count) ->
    Count.

%% Get distinct destination ports from SrcIP since Cutoff
distinct_ports(SrcIP, Cutoff) ->
    StartKey = {SrcIP, Cutoff, 0},
    collect_ports(ets:next(?GUARD_CONNS, StartKey), SrcIP, sets:new()).

collect_ports('$end_of_table', _, Ports) ->
    sets:to_list(Ports);
collect_ports({IP, _, _} = Key, SrcIP, Ports) when IP =:= SrcIP ->
    case ets:lookup(?GUARD_CONNS, Key) of
        [{_, DstPort}] ->
            collect_ports(
                ets:next(?GUARD_CONNS, Key),
                SrcIP,
                sets:add_element(DstPort, Ports)
            );
        [] ->
            collect_ports(ets:next(?GUARD_CONNS, Key), SrcIP, Ports)
    end;
collect_ports(_, _, Ports) ->
    sets:to_list(Ports).

%% ===================================================================
%% Cleanup
%% ===================================================================

do_cleanup(
    #{
        flood_window := FW,
        scan_window := SW,
        slow_window := SlW,
        slow_tracker := Tracker,
        bans_expired := Exp
    } = State
) ->
    Now = erlang:system_time(second),

    %% Remove connection events older than the largest window
    MaxWindow = max(max(FW, SW), SlW),
    Cutoff = Now - MaxWindow,
    ExpiredConns = delete_before(ets:first(?GUARD_CONNS), Cutoff, 0),

    %% Remove expired bans
    ExpiredBans = cleanup_bans(Now),

    case ExpiredConns > 0 orelse ExpiredBans > 0 of
        true ->
            logger:debug(
                "[ct_guard] Cleanup: ~p events, ~p bans expired",
                [ExpiredConns, ExpiredBans]
            );
        false ->
            ok
    end,

    %% Clean up expired slow-scan tracker entries
    SlowCutoff = Now - SlW,
    Tracker2 = maps:filter(fun(_IP, #{first_seen := FS}) ->
        FS > SlowCutoff
    end, Tracker),

    State#{bans_expired := Exp + ExpiredBans, slow_tracker := Tracker2}.

delete_before('$end_of_table', _, Count) ->
    Count;
delete_before({_IP, Ts, _} = Key, Cutoff, Count) when Ts < Cutoff ->
    Next = ets:next(?GUARD_CONNS, Key),
    ets:delete(?GUARD_CONNS, Key),
    delete_before(Next, Cutoff, Count + 1);
delete_before(_, _, Count) ->
    Count.

cleanup_bans(Now) ->
    ets:foldl(
        fun({IP, _, ExpiresAt, _}, Count) ->
            case ExpiresAt =< Now of
                true ->
                    ets:delete(?GUARD_BANS, IP),
                    _ = try_unban(IP),
                    broadcast({ct_guard_unban, #{ip => IP}}),
                    Count + 1;
                false ->
                    Count
            end
        end,
        0,
        ?GUARD_BANS
    ).

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

broadcast(Msg) ->
    try
        Members = pg:get_members(erlkoenig_nft, ct_guard_events),
        _ = [Pid ! Msg || Pid <- Members],
        ok
    catch
        C:R ->
            logger:warning("[ct_guard] broadcast failed: ~p:~p", [C, R]),
            ok
    end.

%% Defensive ETS creation: if the table already exists (restart race),
%% reuse it instead of crashing with badarg.
ensure_ets(Name, Opts) ->
    case ets:whereis(Name) of
        undefined -> ets:new(Name, Opts);
        _Tid -> Name
    end.
