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

-module(nfnl_server).
-moduledoc """
Supervised nf_tables Netlink connection.

Manages a persistent Netlink socket and provides synchronous
operations for sending batched nf_tables messages to the kernel.

Can be started with a registered name:
    nfnl_server:start_link([{name, erlkoenig_srv}])

Then used by name from any process:
    nfnl_server:apply_msgs(erlkoenig_srv, [...])
""".

-behaviour(gen_server).

-export([start_link/0,
         start_link/1,
         apply_msgs/2,
         get_counter/4,
         get_counter_reset/4,
         stop/1]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2]).

-export_type([server_ref/0]).

%% --- Types ---

-type server_ref() :: pid() | atom().

-type state() :: #{
    socket := socket:socket(),
    seq    := non_neg_integer()
}.

%% --- Constants ---

-define(RECV_TIMEOUT, 5000).

%% --- Public API ---

-doc "Start the server with default options.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

-doc """
Start the server with options.

Options:
    {name, atom()} - Register the server with a name.
""".
-spec start_link(list()) -> {ok, pid()} | {error, term()}.
start_link(Opts) when is_list(Opts) ->
    case proplists:get_value(name, Opts) of
        undefined ->
            gen_server:start_link(?MODULE, Opts, []);
        Name when is_atom(Name) ->
            gen_server:start_link({local, Name}, ?MODULE, Opts, [])
    end.

-doc """
Send a list of nf_tables messages as an atomic batch.

Each message is a function that takes a sequence number and returns
the encoded binary. The server assigns sequence numbers, wraps
everything in batch begin/end, sends it, and waits for all ACKs.

Returns `ok` if all messages succeeded, or `{error, Reason}` with
the first error encountered.
""".
-spec apply_msgs(server_ref(), [fun((non_neg_integer()) -> binary())]) ->
    ok | {error, term()}.
apply_msgs(Server, MsgFuns) when is_list(MsgFuns) ->
    gen_server:call(Server, {apply_msgs, MsgFuns}, ?RECV_TIMEOUT + 2000).

-doc """
Read a named counter without resetting it.

Returns the cumulative kernel values. The counter keeps counting.
""".
-spec get_counter(server_ref(), 0..255, binary(), binary()) ->
    {ok, map()} | {error, term()}.
get_counter(Server, Family, Table, Name) ->
    gen_server:call(Server, {get_counter, Family, Table, Name}, ?RECV_TIMEOUT + 2000).

-doc """
Read a named counter and atomically reset it to zero.

Delegates to nft_object:get_counter_reset/4 through the shared
Netlink socket. Safe to call from any process.
""".
-spec get_counter_reset(server_ref(), 0..255, binary(), binary()) ->
    {ok, map()} | {error, term()}.
get_counter_reset(Server, Family, Table, Name) ->
    gen_server:call(Server, {get_counter_reset, Family, Table, Name}, ?RECV_TIMEOUT + 2000).

-doc "Stop the server.".
-spec stop(server_ref()) -> ok.
stop(Server) ->
    gen_server:stop(Server).

%% --- gen_server callbacks ---

-spec init(list()) -> {ok, state()} | {stop, term()}.
init(_Opts) ->
    case nfnl_socket:open() of
        {ok, Sock} ->
            Seq = erlang:system_time(second) band 16#FFFFFFFF,
            {ok, #{socket => Sock, seq => Seq}};
        {error, Reason} ->
            {stop, {socket_open_failed, Reason}}
    end.

-spec handle_call(term(), {pid(), term()}, state()) ->
    {reply, term(), state()}.
handle_call({apply_msgs, MsgFuns}, _From, #{socket := Sock, seq := Seq} = State) ->
    {Msgs, NextSeq} = build_msgs(MsgFuns, Seq + 1, []),
    Batch = nft_batch:wrap(Msgs, Seq),
    Result = case nfnl_socket:send(Sock, Batch) of
        ok ->
            collect_and_parse(Sock, length(MsgFuns));
        {error, _} = Err ->
            Err
    end,
    {reply, Result, State#{seq => NextSeq + 1}};
handle_call({get_counter, Family, Table, Name}, _From, #{socket := Sock} = State) ->
    Result = nft_object:get_counter(Sock, Family, Table, Name),
    {reply, Result, State};
handle_call({get_counter_reset, Family, Table, Name}, _From, #{socket := Sock} = State) ->
    Result = nft_object:get_counter_reset(Sock, Family, Table, Name),
    {reply, Result, State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, #{socket := Sock}) ->
    nfnl_socket:close(Sock).

%% --- Internal ---

-spec build_msgs([fun((non_neg_integer()) -> binary())],
                 non_neg_integer(), [binary()]) ->
    {[binary()], non_neg_integer()}.
build_msgs([], Seq, Acc) ->
    {lists:reverse(Acc), Seq};
build_msgs([Fun | Rest], Seq, Acc) ->
    Msg = Fun(Seq),
    build_msgs(Rest, Seq + 1, [Msg | Acc]).

-spec collect_and_parse(socket:socket(), non_neg_integer()) ->
    ok | {error, term()}.
collect_and_parse(Sock, ExpectedCount) ->
    collect_loop(Sock, ExpectedCount, []).

-spec collect_loop(socket:socket(), non_neg_integer(), [binary()]) ->
    ok | {error, term()}.
collect_loop(_Sock, 0, _Acc) ->
    ok;
collect_loop(Sock, Remaining, Acc) ->
    case nfnl_socket:recv(Sock) of
        {ok, Data} ->
            Results = nfnl_response:parse(Data),
            case check_results(Results) of
                {ok, Count} ->
                    Left = Remaining - Count,
                    if Left =< 0 -> ok;
                       true -> collect_loop(Sock, Left, Acc)
                    end;
                {error, _} = Err ->
                    Err
            end;
        {error, timeout} ->
            ok;
        {error, _} = Err ->
            Err
    end.

-spec check_results(nfnl_response:response()) ->
    {ok, non_neg_integer()} | {error, term()}.
check_results(Results) ->
    check_results(Results, 0).

-spec check_results(nfnl_response:response(), non_neg_integer()) ->
    {ok, non_neg_integer()} | {error, term()}.
check_results([], Count) ->
    {ok, Count};
check_results([ok | Rest], Count) ->
    check_results(Rest, Count + 1);
check_results([{error, _} = Err | _Rest], _Count) ->
    Err.
