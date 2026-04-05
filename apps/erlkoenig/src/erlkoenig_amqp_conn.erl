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

-module(erlkoenig_amqp_conn).
-moduledoc """
AMQP connection owner.

Manages the single TCP connection to RabbitMQ. Children (publisher,
commander, auditor) request channels via open_channel/0.

Reconnects with exponential backoff (5s, 10s, 20s, 40s, cap 60s).
Uses amqp_client at runtime — compiles without it.
""".

-behaviour(gen_server).

-include_lib("amqp_client/include/amqp_client.hrl").

-export([start_link/1, open_channel/0, status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(state, {
    config     :: map(),
    connection :: pid() | undefined,
    status     :: connected | disconnected,
    reconnects :: non_neg_integer()
}).

-define(BACKOFF_INIT, 5000).
-define(BACKOFF_MAX, 60000).

%%====================================================================
%% API
%%====================================================================

-spec start_link(map()) -> gen_server:start_ret().
start_link(Config) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

-spec open_channel() -> {ok, pid()} | {error, disconnected | term()}.
open_channel() ->
    gen_server:call(?MODULE, open_channel, 5000).

-spec status() -> connected | disconnected.
status() ->
    gen_server:call(?MODULE, status, 5000).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init(Config) ->
    State = #state{config = Config, connection = undefined,
                   status = disconnected, reconnects = 0},
    self() ! connect,
    {ok, State}.

handle_call(open_channel, _From, #state{status = disconnected} = State) ->
    {reply, {error, disconnected}, State};

handle_call(open_channel, _From, #state{connection = Conn} = State) ->
    try amqp_connection:open_channel(Conn) of
        {ok, Channel} ->
            {reply, {ok, Channel}, State};
        {error, Reason} ->
            {reply, {error, Reason}, State}
    catch _:Err ->
        {reply, {error, Err}, State}
    end;

handle_call(status, _From, #state{status = S} = State) ->
    {reply, S, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(connect, State) ->
    case do_connect(State#state.config) of
        {ok, Conn} ->
            _Ref = monitor(process, Conn),
            logger:info("erlkoenig_amqp_conn: connected to ~s:~p",
                        [maps:get(host, State#state.config, "localhost"),
                         maps:get(port, State#state.config, 5672)]),
            {noreply, State#state{connection = Conn, status = connected,
                                  reconnects = 0}};
        {error, Reason} ->
            N = State#state.reconnects + 1,
            Delay = min(?BACKOFF_MAX, ?BACKOFF_INIT * (1 bsl min(N - 1, 4))),
            logger:warning("erlkoenig_amqp_conn: connect failed (~p), retry in ~ps",
                           [Reason, Delay div 1000]),
            erlang:send_after(Delay, self(), connect),
            {noreply, State#state{status = disconnected, reconnects = N}}
    end;

handle_info({'DOWN', _Ref, process, Conn, Reason},
            #state{connection = Conn} = State) ->
    logger:warning("erlkoenig_amqp_conn: connection lost: ~p", [Reason]),
    erlang:send_after(?BACKOFF_INIT, self(), connect),
    {noreply, State#state{connection = undefined, status = disconnected,
                          reconnects = 0}};

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, #state{connection = undefined}) ->
    ok;
terminate(_Reason, #state{connection = Conn}) ->
    catch amqp_connection:close(Conn),
    ok.

%%====================================================================
%% Internal
%%====================================================================

-spec do_connect(map()) -> {ok, pid()} | {error, term()}.
do_connect(Config) ->
    Params = #amqp_params_network{
        username  = maps:get(user, Config, <<"guest">>),
        password  = maps:get(password, Config, <<"guest">>),
        virtual_host = maps:get(vhost, Config, <<"/">>),
        host      = maps:get(host, Config, "localhost"),
        port      = maps:get(port, Config, 5672),
        heartbeat = 30
    },
    try amqp_connection:start(Params) of
        {ok, Conn} -> {ok, Conn};
        {error, _} = Err -> Err
    catch _:Err -> {error, Err}
    end.
