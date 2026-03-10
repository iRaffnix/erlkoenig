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

-export([ban/1,
         unban/1,
         rates/0,
         status/0,
         reload/0,
         %% Conntrack API
         ct_count/0,
         ct_count/1,
         ct_top/1,
         ct_connections/0,
         ct_mode/0,
         ct_stats/0,
         %% Guard API
         guard_stats/0,
         guard_banned/0]).

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
    ok = erlk_firewall:ban(IP),
    %% Also kill existing connections from this IP
    case erlk_ip:normalize(IP) of
        {ok, Bin} ->
            try erlk_ct:kill_by_src(Bin)
            catch exit:{noproc, _} -> ok
            end;
        _ -> ok
    end,
    ok.

-doc "Remove an IP address from the blocklist (IPv4 or IPv6).".
-spec unban(inet:ip_address() | binary() | string()) -> ok | {error, term()}.
unban(IP) ->
    erlk_firewall:unban(IP).

-doc "Get current rates for all watched counters.".
-spec rates() -> #{binary() => map()}.
rates() ->
    erlk_firewall:rates().

-doc "Get firewall status.".
-spec status() -> map().
status() ->
    erlk_firewall:status().

-doc """
Reload firewall config from priv/firewall.term.

Re-applies the full config without restarting the application.
Existing connections are preserved.
""".
-spec reload() -> ok | {error, term()}.
reload() ->
    erlk_firewall:reload().

%% --- Conntrack API ---

-doc "Total number of tracked connections.".
-spec ct_count() -> non_neg_integer().
ct_count() ->
    erlk_ct:count().

-doc "Number of connections from a specific source IP.".
-spec ct_count(inet:ip_address() | binary() | string()) -> non_neg_integer().
ct_count(IP) ->
    case erlk_ip:normalize(IP) of
        {ok, Bin} -> erlk_ct:count_by_src(Bin);
        _ -> 0
    end.

-doc "Top N source IPs by active connection count.".
-spec ct_top(pos_integer()) -> [{binary(), non_neg_integer()}].
ct_top(N) ->
    erlk_ct:top_sources(N).

-doc "List all tracked connections (only in full mode).".
-spec ct_connections() -> [map()].
ct_connections() ->
    erlk_ct:connections().

-doc "Current tracking mode: full or aggregate.".
-spec ct_mode() -> full | aggregate.
ct_mode() ->
    erlk_ct:mode().

-doc "Conntrack operational statistics.".
-spec ct_stats() -> map().
ct_stats() ->
    erlk_ct:stats().

%% --- Guard API ---

-doc "Guard detection and ban statistics.".
-spec guard_stats() -> map().
guard_stats() ->
    erlk_ct_guard:stats().

-doc "List all IPs currently banned by the guard.".
-spec guard_banned() -> [map()].
guard_banned() ->
    erlk_ct_guard:banned().


