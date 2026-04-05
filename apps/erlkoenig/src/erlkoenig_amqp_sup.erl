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

-module(erlkoenig_amqp_sup).
-moduledoc """
Supervisor for the AMQP integration subtree.

Uses rest_for_one: if the connection dies, the publisher dies too
and both restart in correct order.

    erlkoenig_amqp_sup (rest_for_one)
    ├── erlkoenig_amqp_conn       Connection owner
    └── erlkoenig_amqp_publisher  Event publisher (+ forwarder handler)

Future phases add workers here without restructuring:
    ├── erlkoenig_amqp_commander  (v2)
    └── erlkoenig_amqp_auditor    (v3)

See ADR-0014.
""".

-behaviour(supervisor).

-export([start_link/1, init/1]).

start_link(Config) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, Config).

init(Config) ->
    SupFlags = #{
        strategy => rest_for_one,
        intensity => 5,
        period => 60
    },
    ConnSpec = #{
        id => erlkoenig_amqp_conn,
        start => {erlkoenig_amqp_conn, start_link, [Config]},
        restart => permanent,
        type => worker,
        shutdown => 5000
    },
    PublisherSpec = #{
        id => erlkoenig_amqp_publisher,
        start => {erlkoenig_amqp_publisher, start_link, [Config]},
        restart => permanent,
        type => worker,
        shutdown => 5000
    },
    NftSubSpec = #{
        id => erlkoenig_amqp_nft_sub,
        start => {erlkoenig_amqp_nft_sub, start_link, []},
        restart => permanent,
        type => worker,
        shutdown => 5000
    },
    {ok, {SupFlags, [ConnSpec, PublisherSpec, NftSubSpec]}}.
