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

-module(erlkoenig_amqp_publisher).
-moduledoc """
AMQP event publisher.

Requests a channel from erlkoenig_amqp_conn, declares the exchange,
and publishes JSON events received via cast from the forwarder.

Linked to its channel — if the channel dies, the publisher dies
and the supervisor restarts it (getting a fresh channel).
""".

-behaviour(gen_server).

-include_lib("amqp_client/include/amqp_client.hrl").

-export([start_link/1, stats/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    channel   :: pid() | undefined,
    exchange  :: binary(),
    published :: non_neg_integer(),
    dropped   :: non_neg_integer(),
    errors    :: non_neg_integer()
}).

%%====================================================================
%% API
%%====================================================================

-spec start_link(map()) -> gen_server:start_ret().
start_link(Config) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

-spec stats() -> map().
stats() ->
    gen_server:call(?MODULE, stats, 5000).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Config) ->
    Exchange = maps:get(exchange, Config, <<"erlkoenig.events">>),
    case erlkoenig_amqp_conn:open_channel() of
        {ok, Channel} ->
            link(Channel),
            ok = declare_exchange(Channel, Exchange),
            _ = install_forwarder(),
            logger:info("erlkoenig_amqp_publisher: ready (exchange=~s)", [Exchange]),
            {ok, #state{channel = Channel, exchange = Exchange,
                        published = 0, dropped = 0, errors = 0}};
        {error, Reason} ->
            logger:warning("erlkoenig_amqp_publisher: no channel: ~p", [Reason]),
            {stop, {no_channel, Reason}}
    end.

handle_call(stats, _From, State) ->
    {reply, #{published => State#state.published,
              dropped => State#state.dropped,
              errors => State#state.errors}, State};

handle_call(_Msg, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast({publish, RoutingKey, JsonBin}, #state{channel = Ch, exchange = Ex} = State) ->
    Publish = #'basic.publish'{exchange = Ex, routing_key = RoutingKey},
    Props = #'P_basic'{delivery_mode = 2},  %% persistent
    Content = #amqp_msg{props = Props, payload = iolist_to_binary(JsonBin)},
    try
        amqp_channel:cast(Ch, Publish, Content),
        {noreply, State#state{published = State#state.published + 1}}
    catch _:Err ->
        logger:warning("erlkoenig_amqp_publisher: publish failed: ~p", [Err]),
        {noreply, State#state{errors = State#state.errors + 1}}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Ch, Reason}, #state{channel = Ch} = State) ->
    logger:warning("erlkoenig_amqp_publisher: channel lost: ~p", [Reason]),
    {stop, {channel_lost, Reason}, State#state{channel = undefined}};

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    _ = erlkoenig_events:unsubscribe(erlkoenig_amqp_forwarder, self()),
    ok.

%%====================================================================
%% Internal
%%====================================================================

install_forwarder() ->
    _ = erlkoenig_events:unsubscribe(erlkoenig_amqp_forwarder, self()),
    erlkoenig_events:subscribe(erlkoenig_amqp_forwarder, self()).

declare_exchange(Channel, Exchange) ->
    Declare = #'exchange.declare'{exchange = Exchange,
                                  type = <<"topic">>,
                                  durable = true},
    try amqp_channel:call(Channel, Declare) of
        #'exchange.declare_ok'{} -> ok;
        _ -> ok
    catch _:Err ->
        logger:warning("erlkoenig_amqp_publisher: exchange_declare failed: ~p", [Err]),
        ok
    end.
