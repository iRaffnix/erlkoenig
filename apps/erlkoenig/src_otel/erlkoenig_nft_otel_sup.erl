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

-module(erlkoenig_nft_otel_sup).
-moduledoc """
Supervisor for the OpenTelemetry extension.

Runs in a separate failure domain from the firewall core. Own restart
budget (3 restarts in 30 seconds). Started conditionally by
erlkoenig_nft_app after the main supervisor.

If this supervisor dies, the firewall continues unaffected.
""".

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-doc "Start the OTel extension supervisor.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    SupFlags = #{
        strategy => one_for_one,
        intensity => 3,
        period => 30
    },
    Children = [
        #{
            id => erlkoenig_nft_otel,
            start => {erlkoenig_nft_otel, start_link, []},
            restart => transient,
            shutdown => 5000,
            type => worker,
            modules => [erlkoenig_nft_otel]
        }
    ],
    {ok, {SupFlags, Children}}.
