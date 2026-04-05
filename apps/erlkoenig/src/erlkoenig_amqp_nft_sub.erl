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

-module(erlkoenig_amqp_nft_sub).
-moduledoc """
Subscribes to erlkoenig_nft pg event groups and forwards
events to the AMQP publisher.

Joins 4 pg groups in the erlkoenig_nft scope:
  - control_events  (ban, unban, reload, etc.)
  - ct_events       (conntrack new/destroy/alert)
  - nflog_events    (logged packets)
  - counter_events  (counter rates, threshold alerts)

Events arrive as plain Erlang messages (pg broadcast).
They are encoded via erlkoenig_amqp_codec and forwarded
to the publisher via gen_server:cast.
""".

-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(GROUPS, [control_events, ct_events, nflog_events, counter_events, ct_guard_events]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    %% Join all nft pg groups — events arrive as plain messages
    lists:foreach(fun(Group) ->
        try
            pg:join(erlkoenig_nft, Group, self()),
            logger:info("erlkoenig_amqp_nft_sub: joined ~p", [Group])
        catch _:Err ->
            logger:warning("erlkoenig_amqp_nft_sub: failed to join ~p: ~p", [Group, Err])
        end
    end, ?GROUPS),
    {ok, #{}}.

handle_call(_Msg, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(Msg, State) ->
    case erlkoenig_amqp_codec:encode(Msg) of
        {ok, RoutingKey, JsonBin} ->
            gen_server:cast(erlkoenig_amqp_publisher, {publish, RoutingKey, JsonBin});
        skip ->
            ok
    end,
    {noreply, State}.

terminate(_Reason, _State) ->
    lists:foreach(fun(Group) ->
        catch pg:leave(erlkoenig_nft, Group, self())
    end, ?GROUPS),
    ok.
