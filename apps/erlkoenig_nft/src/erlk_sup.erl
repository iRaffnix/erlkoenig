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

-module(erlk_sup).
-moduledoc """
Top-level supervisor for the Erlkoenig application.

Uses rest_for_one strategy. Children are ordered by dependency:

    1. {pg, erlkoenig_nft}  — Process group scope (events)
    2. erlk_srv            — Shared Netlink server
    3. erlk_nflog          — NFLOG packet receiver (optional)
    4. erlk_ct             — Conntrack event monitor
    5. erlk_ct_guard       — Automatic threat detection
    6. erlk_watch_sup      — Dynamic supervisor for counters
    7. erlk_firewall       — Config owner, lifecycle manager

If erlk_srv crashes, everything after it restarts. The firewall
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
            id       => erlk_srv,
            start    => {nfnl_server, start_link, [[{name, erlk_srv}]]},
            restart  => permanent,
            shutdown => 5000,
            type     => worker,
            modules  => [nfnl_server]
        },
        %% 3. NFLOG receiver — optional, won't take down the tree
        #{
            id       => erlk_nflog,
            start    => {erlk_nflog, start_link, [1]},
            restart  => transient,
            shutdown => 5000,
            type     => worker,
            modules  => [erlk_nflog]
        },
        %% 4. Conntrack event receiver — tracks connections in real time
        #{
            id       => erlk_ct,
            start    => {erlk_ct, start_link, []},
            restart  => transient,
            shutdown => 5000,
            type     => worker,
            modules  => [erlk_ct]
        },
        %% 5. Conntrack guard — automatic threat detection
        #{
            id       => erlk_ct_guard,
            start    => {erlk_ct_guard, start_link, [#{}]},
            restart  => transient,
            shutdown => 5000,
            type     => worker,
            modules  => [erlk_ct_guard]
        },
        %% 6. Dynamic supervisor for per-counter workers
        #{
            id       => erlk_watch_sup,
            start    => {erlk_watch_sup, start_link, []},
            restart  => permanent,
            shutdown => infinity,
            type     => supervisor,
            modules  => [erlk_watch_sup]
        },
        %% 7. Firewall config owner — last, depends on all above
        #{
            id       => erlk_firewall,
            start    => {erlk_firewall, start_link, []},
            restart  => permanent,
            shutdown => 10000,
            type     => worker,
            modules  => [erlk_firewall]
        }
    ],
    {ok, {SupFlags, Children}}.
