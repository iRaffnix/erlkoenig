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

-module(erlkoenig_nft).
-moduledoc """
Public API for the Erlkoenig firewall.

This is the only module external code needs to interact with.
All functions delegate to the supervised gen_servers.

    %% Ban an IP address (blocks new + kills existing connections)
    erlkoenig_nft:ban("10.0.0.5").

    %% Get counter rates
    erlkoenig_nft:rates().

    %% Connection tracking
    erlkoenig_nft:ct_count().          %% total active connections
    erlkoenig_nft:ct_top(10).          %% top 10 source IPs by connection count
    erlkoenig_nft:ct_stats().          %% operational stats
""".

-export([
    ban/1,
    unban/1,
    rates/0,
    status/0,
    reload/0,
    %% Listing API
    list_chains/0,
    list_sets/0,
    list_set/1,
    list_counters/0,
    %% Element API
    add_element/2,
    del_element/2,
    %% Diff API
    diff_live/0,
    %% Audit API
    audit_log/0,
    audit_log/1,
    %% Conntrack API
    ct_count/0,
    ct_count/1,
    ct_top/1,
    ct_connections/0,
    ct_mode/0,
    ct_stats/0,
    %% Guard API
    guard_stats/0,
    guard_banned/0
]).

%% --- Firewall API ---

-doc """
Add an IP address to the blocklist and kill existing connections.

Accepts IPv4 or IPv6 as tuple, binary, or string:
    erlkoenig_nft:ban({10, 0, 0, 5})
    erlkoenig_nft:ban(<<10, 0, 0, 5>>)
    erlkoenig_nft:ban("10.0.0.5")
    erlkoenig_nft:ban("2001:db8::1")
""".
-spec ban(inet:ip_address() | binary() | string()) -> ok | {error, term()}.
ban(IP) ->
    IPBin = iolist_to_binary(io_lib:format("~s", [IP])),
    Result =
        case erlkoenig_nft_firewall:ban(IP) of
            ok ->
                %% Kill existing connections from this IP
                _ =
                    case erlkoenig_nft_ip:normalize(IP) of
                        {ok, Bin} ->
                            try
                                erlkoenig_nft_ct:kill_by_src(Bin)
                            catch
                                exit:{noproc, _} -> ok
                            end;
                        _ ->
                            ok
                    end,
                ok;
            {error, _} = Err ->
                Err
        end,
    erlkoenig_nft_events:notify_control(ban, Result, #{ip => IPBin}),
    Result.

-doc "Remove an IP address from the blocklist (IPv4 or IPv6).".
-spec unban(inet:ip_address() | binary() | string()) -> ok | {error, term()}.
unban(IP) ->
    IPBin = iolist_to_binary(io_lib:format("~s", [IP])),
    Result =
        case erlkoenig_nft_firewall:unban(IP) of
            ok -> ok;
            {error, _} = Err -> Err
        end,
    erlkoenig_nft_events:notify_control(unban, Result, #{ip => IPBin}),
    Result.

-doc "Get current rates for all watched counters.".
-spec rates() -> #{binary() => map()}.
rates() ->
    erlkoenig_nft_firewall:rates().

-doc "Get firewall status.".
-spec status() -> map().
status() ->
    erlkoenig_nft_firewall:status().

-doc """
Reload firewall config from etc/firewall.term.

Re-applies the full config without restarting the application.
Existing connections are preserved.
""".
-spec reload() -> ok | {error, term()}.
reload() ->
    Result =
        case erlkoenig_nft_firewall:reload() of
            ok -> ok;
            {error, _} = Err -> Err
        end,
    erlkoenig_nft_events:notify_control(reload, Result, #{}),
    Result.

%% --- Listing API ---

-doc "List chains with hook, type, policy, and rule count.".
-spec list_chains() -> [map()].
list_chains() ->
    erlkoenig_nft_firewall:list_chains().

-doc "List named sets with their types.".
-spec list_sets() -> [map()].
list_sets() ->
    erlkoenig_nft_firewall:list_sets().

-doc "Show elements of a named set (config-known elements).".
-spec list_set(binary() | [byte()]) -> {ok, map()} | {error, term()}.
list_set(Name) ->
    erlkoenig_nft_firewall:list_set(Name).

-doc "List counters with current rate values.".
-spec list_counters() -> [map()].
list_counters() ->
    erlkoenig_nft_firewall:list_counters().

%% --- Element API ---

-doc "Add an element to a named set.".
-spec add_element(binary() | [byte()], binary() | string()) -> ok | {error, term()}.
add_element(SetName, Value) ->
    SetBin = iolist_to_binary([SetName]),
    ValBin = iolist_to_binary(io_lib:format("~s", [Value])),
    Result =
        case erlkoenig_nft_firewall:add_element(SetName, Value) of
            ok -> ok;
            {error, _} = Err -> Err
        end,
    erlkoenig_nft_events:notify_control(add_element, Result, #{set => SetBin, value => ValBin}),
    Result.

-doc "Delete an element from a named set.".
-spec del_element(binary() | [byte()], binary() | string()) -> ok | {error, term()}.
del_element(SetName, Value) ->
    SetBin = iolist_to_binary([SetName]),
    ValBin = iolist_to_binary(io_lib:format("~s", [Value])),
    Result =
        case erlkoenig_nft_firewall:del_element(SetName, Value) of
            ok -> ok;
            {error, _} = Err -> Err
        end,
    erlkoenig_nft_events:notify_control(del_element, Result, #{set => SetBin, value => ValBin}),
    Result.

%% --- Diff API ---

-doc "Compare running kernel state against config. Returns a list of diffs.".
-spec diff_live() -> [map()].
diff_live() ->
    erlkoenig_nft_firewall:diff_live().

%% --- Audit API ---

-doc "Get all audit log entries.".
-spec audit_log() -> [#{action := atom(), details := map(), time := binary()}].
audit_log() ->
    erlkoenig_nft_audit:entries().

-doc "Get the last N audit log entries.".
-spec audit_log(pos_integer()) -> [#{action := atom(), details := map(), time := binary()}].
audit_log(N) ->
    erlkoenig_nft_audit:entries(N).

%% --- Conntrack API ---

-doc "Total number of tracked connections.".
-spec ct_count() -> non_neg_integer().
ct_count() ->
    erlkoenig_nft_ct:count().

-doc "Number of connections from a specific source IP.".
-spec ct_count(inet:ip_address() | binary() | string()) -> non_neg_integer().
ct_count(IP) ->
    case erlkoenig_nft_ip:normalize(IP) of
        {ok, Bin} -> erlkoenig_nft_ct:count_by_src(Bin);
        _ -> 0
    end.

-doc "Top N source IPs by active connection count.".
-spec ct_top(pos_integer()) -> [{binary(), non_neg_integer()}].
ct_top(N) ->
    erlkoenig_nft_ct:top_sources(N).

-doc "List all tracked connections (only in full mode).".
-spec ct_connections() -> [map()].
ct_connections() ->
    erlkoenig_nft_ct:connections().

-doc "Current tracking mode: full or aggregate.".
-spec ct_mode() -> full | aggregate.
ct_mode() ->
    erlkoenig_nft_ct:mode().

-doc "Conntrack operational statistics.".
-spec ct_stats() -> map().
ct_stats() ->
    erlkoenig_nft_ct:stats().

%% --- Guard API ---

-doc "Guard detection and ban statistics.".
-spec guard_stats() -> map().
guard_stats() ->
    erlkoenig_nft_ct_guard:stats().

-doc "List all IPs currently banned by the guard.".
-spec guard_banned() -> [map()].
guard_banned() ->
    erlkoenig_nft_ct_guard:banned().
