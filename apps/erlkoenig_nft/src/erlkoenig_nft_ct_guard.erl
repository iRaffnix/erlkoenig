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

-define(DEFAULT_CONN_FLOOD, {50, 10}).     %% 50 conns in 10s
-define(DEFAULT_PORT_SCAN,  {20, 60}).     %% 20 ports in 60s
-define(DEFAULT_BAN_DURATION, 3600).       %% 1 hour
-define(DEFAULT_CLEANUP_INTERVAL, 30000).  %% 30 seconds
-define(DEFAULT_WHITELIST, []).

%% ETS tables
-define(GUARD_CONNS, erlkoenig_nft_ct_guard_conns).  %% {SrcIP, Timestamp, DstPort}
-define(GUARD_BANS,  erlkoenig_nft_ct_guard_bans).   %% {SrcIP, BannedAt, ExpiresAt, Reason}

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
    %% Parse config
    {FloodMax, FloodWindow} = maps:get(conn_flood, Config, ?DEFAULT_CONN_FLOOD),
    {ScanMax, ScanWindow} = maps:get(port_scan, Config, ?DEFAULT_PORT_SCAN),
    BanDuration = maps:get(ban_duration, Config, ?DEFAULT_BAN_DURATION),
    CleanupMs = maps:get(cleanup_interval, Config, ?DEFAULT_CLEANUP_INTERVAL),
    Whitelist = normalize_whitelist(maps:get(whitelist, Config, ?DEFAULT_WHITELIST)),

    %% Create ETS tables
    %% Conn tracking: ordered_set for efficient time-range queries
    ets:new(?GUARD_CONNS, [named_table, ordered_set, public]),
    %% Ban tracking: set keyed by IP
    ets:new(?GUARD_BANS, [named_table, set, public]),

    %% Subscribe to conntrack events
    pg:join(erlkoenig_nft, ct_events, self()),

    %% Start cleanup timer
    erlang:send_after(CleanupMs, self(), cleanup),

    State = #{
        flood_max     => FloodMax,
        flood_window  => FloodWindow,
        scan_max      => ScanMax,
        scan_window   => ScanWindow,
        ban_duration  => BanDuration,
        cleanup_ms    => CleanupMs,
        whitelist     => Whitelist,
        %% Stats
        events_seen   => 0,
        floods_detected => 0,
        scans_detected  => 0,
        bans_issued   => 0,
        bans_expired  => 0
    },

    logger:notice("[ct_guard] Started: flood=~p/~ps, scan=~p/~ps, ban=~ps",
                  [FloodMax, FloodWindow, ScanMax, ScanWindow, BanDuration]),

    {ok, State}.

handle_call(stats, _From, State) ->
    #{events_seen := Seen, floods_detected := Floods,
      scans_detected := Scans, bans_issued := Issued,
      bans_expired := Expired, flood_max := FM, flood_window := FW,
      scan_max := SM, scan_window := SW, ban_duration := BD} = State,
    Stats = #{
        events_seen => Seen,
        floods_detected => Floods,
        scans_detected => Scans,
        bans_issued => Issued,
        bans_expired => Expired,
        active_bans => ets:info(?GUARD_BANS, size),
        tracked_events => ets:info(?GUARD_CONNS, size),
        config => #{
            conn_flood => {FM, FW},
            port_scan => {SM, SW},
            ban_duration => BD
        }
    },
    {reply, Stats, State};

handle_call(banned, _From, State) ->
    Now = erlang:system_time(second),
    Bans = ets:foldl(fun({IP, BannedAt, ExpiresAt, Reason}, Acc) ->
        Remaining = max(0, ExpiresAt - Now),
        [#{ip => erlkoenig_nft_ip:format(IP),
           ip_raw => IP,
           reason => Reason,
           banned_at => BannedAt,
           expires_at => ExpiresAt,
           remaining_seconds => Remaining} | Acc]
    end, [], ?GUARD_BANS),
    {reply, Bans, State};

handle_call({reconfigure, Config}, _From, State) ->
    {FloodMax, FloodWindow} = maps:get(conn_flood, Config, {maps:get(flood_max, State), maps:get(flood_window, State)}),
    {ScanMax, ScanWindow} = maps:get(port_scan, Config, {maps:get(scan_max, State), maps:get(scan_window, State)}),
    BanDuration = maps:get(ban_duration, Config, maps:get(ban_duration, State)),
    Whitelist = case maps:find(whitelist, Config) of
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
    logger:notice("[ct_guard] Reconfigured: flood=~p/~ps, scan=~p/~ps, ban=~ps",
                  [FloodMax, FloodWindow, ScanMax, ScanWindow, BanDuration]),
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

            %% Check thresholds
            State3 = check_flood(SrcIP, Now, State2),
            State4 = check_port_scan(SrcIP, Now, State3),

            {noreply, State4}
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
            %% Unban in firewall
            try_unban(SrcIP),
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
%% Ban Management
%% ===================================================================

ban_ip(SrcIP, Reason, #{ban_duration := Duration,
                         bans_issued := Issued} = State) ->
    %% Check not already banned
    case is_banned(SrcIP) of
        true ->
            State;
        false ->
            Now = erlang:system_time(second),
            ExpiresAt = Now + Duration,

            %% Record ban
            ets:insert(?GUARD_BANS, {SrcIP, Now, ExpiresAt, Reason}),

            %% Apply ban in firewall
            try_ban(SrcIP),

            %% Schedule auto-unban
            erlang:send_after(Duration * 1000, self(), {unban, SrcIP}),

            %% Update stats
            StatKey = case Reason of
                conn_flood -> floods_detected;
                port_scan -> scans_detected
            end,
            DetectCount = maps:get(StatKey, State, 0),

            logger:warning("[ct_guard] BANNED ~s reason=~p duration=~ps",
                          [erlkoenig_nft_ip:format(SrcIP), Reason, Duration]),

            %% Broadcast alert
            broadcast({ct_guard_ban, #{
                ip => SrcIP,
                reason => Reason,
                duration => Duration,
                expires_at => ExpiresAt
            }}),

            State#{bans_issued := Issued + 1, StatKey := DetectCount + 1}
    end.

is_banned(SrcIP) ->
    ets:member(?GUARD_BANS, SrcIP).

try_ban(SrcIP) ->
    try
        erlkoenig_nft:ban(SrcIP)
    catch
        _:_ -> ok
    end.

try_unban(SrcIP) ->
    try
        erlkoenig_nft:unban(SrcIP)
    catch
        _:_ -> ok
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

count_range('$end_of_table', _, _, Count) -> Count;
count_range({IP, _, _} = Key, SrcIP, EndKey, Count) when IP =:= SrcIP ->
    count_range(ets:next(?GUARD_CONNS, Key), SrcIP, EndKey, Count + 1);
count_range(_, _, _, Count) -> Count.

%% Get distinct destination ports from SrcIP since Cutoff
distinct_ports(SrcIP, Cutoff) ->
    StartKey = {SrcIP, Cutoff, 0},
    collect_ports(ets:next(?GUARD_CONNS, StartKey), SrcIP, sets:new()).

collect_ports('$end_of_table', _, Ports) -> sets:to_list(Ports);
collect_ports({IP, _, _} = Key, SrcIP, Ports) when IP =:= SrcIP ->
    case ets:lookup(?GUARD_CONNS, Key) of
        [{_, DstPort}] ->
            collect_ports(ets:next(?GUARD_CONNS, Key), SrcIP,
                         sets:add_element(DstPort, Ports));
        [] ->
            collect_ports(ets:next(?GUARD_CONNS, Key), SrcIP, Ports)
    end;
collect_ports(_, _, Ports) -> sets:to_list(Ports).

%% ===================================================================
%% Cleanup
%% ===================================================================

do_cleanup(#{flood_window := FW, scan_window := SW,
             bans_expired := Exp} = State) ->
    Now = erlang:system_time(second),

    %% Remove connection events older than the largest window
    MaxWindow = max(FW, SW),
    Cutoff = Now - MaxWindow,
    ExpiredConns = delete_before(ets:first(?GUARD_CONNS), Cutoff, 0),

    %% Remove expired bans
    ExpiredBans = cleanup_bans(Now),

    case ExpiredConns > 0 orelse ExpiredBans > 0 of
        true ->
            logger:debug("[ct_guard] Cleanup: ~p events, ~p bans expired",
                        [ExpiredConns, ExpiredBans]);
        false ->
            ok
    end,

    State#{bans_expired := Exp + ExpiredBans}.

delete_before('$end_of_table', _, Count) -> Count;
delete_before({_IP, Ts, _} = Key, Cutoff, Count) when Ts < Cutoff ->
    Next = ets:next(?GUARD_CONNS, Key),
    ets:delete(?GUARD_CONNS, Key),
    delete_before(Next, Cutoff, Count + 1);
delete_before(_, _, Count) -> Count.

cleanup_bans(Now) ->
    ets:foldl(fun({IP, _, ExpiresAt, _}, Count) ->
        case ExpiresAt =< Now of
            true ->
                ets:delete(?GUARD_BANS, IP),
                try_unban(IP),
                Count + 1;
            false ->
                Count
        end
    end, 0, ?GUARD_BANS).

%% ===================================================================
%% Whitelist
%% ===================================================================

normalize_whitelist(List) ->
    lists:filtermap(fun(Entry) ->
        case erlkoenig_nft_ip:normalize(Entry) of
            {ok, Bin} -> {true, Bin};
            {error, _} -> false
        end
    end, List).

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
        _:_ -> ok
    end.
