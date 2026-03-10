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

-module(erlkoenig_nft_watch_sup).
-moduledoc """
Dynamic supervisor for erlkoenig_nft_counter workers.

Manages one erlkoenig_nft_counter process per named nf_tables counter.
Uses one_for_one strategy — if a counter worker crashes, only
that counter restarts. Others keep running.

Counter workers are started dynamically by erlkoenig_nft_firewall during
boot via start_counter/1.

    erlkoenig_nft_watch_sup:start_counter(#{
        name   => <<"ssh">>,
        family => 1,
        table  => <<"erlkoenig">>,
        interval => 2000
    })
""".

-behaviour(supervisor).

-export([start_link/0,
         start_counter/1,
         stop_counters/0]).

-export([init/1]).

%% --- Public API ---

-doc "Start the counter supervisor.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc """
Start a counter worker under this supervisor.

Config is passed to erlkoenig_nft_counter:start_link/1.
""".
-spec start_counter(map()) -> {ok, pid()} | {error, term()}.
start_counter(Config) ->
    supervisor:start_child(?MODULE, [Config]).

-doc "Terminate all counter workers.".
-spec stop_counters() -> ok.
stop_counters() ->
    [supervisor:terminate_child(?MODULE, Pid)
     || {_, Pid, _, _} <- supervisor:which_children(?MODULE),
        is_pid(Pid)],
    ok.

%% --- supervisor callback ---

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    SupFlags = #{
        strategy  => simple_one_for_one,
        intensity => 10,
        period    => 60
    },
    ChildSpec = #{
        id       => erlkoenig_nft_counter,
        start    => {erlkoenig_nft_counter, start_link, []},
        restart  => permanent,
        shutdown => 5000,
        type     => worker,
        modules  => [erlkoenig_nft_counter]
    },
    {ok, {SupFlags, [ChildSpec]}}.
