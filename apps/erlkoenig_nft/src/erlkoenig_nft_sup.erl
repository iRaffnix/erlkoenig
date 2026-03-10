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

-module(erlkoenig_nft_sup).
-moduledoc """
Top-level supervisor for the Erlkoenig application.

Uses rest_for_one strategy. Children are ordered by dependency:

    1. {pg, erlkoenig_nft}  — Process group scope (events)
    2. erlkoenig_nft_srv            — Shared Netlink server
    3. erlkoenig_nft_nflog          — NFLOG packet receiver (optional)
    4. erlkoenig_nft_ct             — Conntrack event monitor
    5. erlkoenig_nft_ct_guard       — Automatic threat detection
    6. erlkoenig_nft_watch_sup      — Dynamic supervisor for counters
    7. erlkoenig_nft_firewall       — Config owner, lifecycle manager

If erlkoenig_nft_srv crashes, everything after it restarts. The firewall
gets re-applied automatically on restart.
""".

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-doc "Start the supervisor.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    SupFlags = #{
        strategy  => rest_for_one,
        intensity => 5,
        period    => 60
    },
    Children = [
        %% 1. pg scope — must be first, others broadcast via pg
        #{
            id       => pg,
            start    => {pg, start_link, [erlkoenig_nft]},
            restart  => permanent,
            shutdown => 5000,
            type     => worker,
            modules  => [pg]
        },
        %% 2. Shared Netlink server — single socket for all ops
        #{
            id       => erlkoenig_nft_srv,
            start    => {nfnl_server, start_link, [[{name, erlkoenig_nft_srv}]]},
            restart  => permanent,
            shutdown => 5000,
            type     => worker,
            modules  => [nfnl_server]
        },
        %% 3. NFLOG receiver — optional, won't take down the tree
        #{
            id       => erlkoenig_nft_nflog,
            start    => {erlkoenig_nft_nflog, start_link, [1]},
            restart  => transient,
            shutdown => 5000,
            type     => worker,
            modules  => [erlkoenig_nft_nflog]
        },
        %% 4. Conntrack event receiver — tracks connections in real time
        #{
            id       => erlkoenig_nft_ct,
            start    => {erlkoenig_nft_ct, start_link, []},
            restart  => transient,
            shutdown => 5000,
            type     => worker,
            modules  => [erlkoenig_nft_ct]
        },
        %% 5. Conntrack guard — automatic threat detection
        #{
            id       => erlkoenig_nft_ct_guard,
            start    => {erlkoenig_nft_ct_guard, start_link, [#{}]},
            restart  => transient,
            shutdown => 5000,
            type     => worker,
            modules  => [erlkoenig_nft_ct_guard]
        },
        %% 6. Dynamic supervisor for per-counter workers
        #{
            id       => erlkoenig_nft_watch_sup,
            start    => {erlkoenig_nft_watch_sup, start_link, []},
            restart  => permanent,
            shutdown => infinity,
            type     => supervisor,
            modules  => [erlkoenig_nft_watch_sup]
        },
        %% 7. Firewall config owner — last, depends on all above
        #{
            id       => erlkoenig_nft_firewall,
            start    => {erlkoenig_nft_firewall, start_link, []},
            restart  => permanent,
            shutdown => 10000,
            type     => worker,
            modules  => [erlkoenig_nft_firewall]
        }
    ],
    {ok, {SupFlags, Children}}.
