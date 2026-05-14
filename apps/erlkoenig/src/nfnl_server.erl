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

-include("erlkoenig_error.hrl").
-include("nft_constants.hrl").

-export([
    start_link/0,
    start_link/1,
    apply_msgs/2,
    get_counter/4,
    get_counter_reset/4,
    list_set_elems/4,
    list_chains/3,
    get_ruleset/2,
    stop/1
]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-export_type([server_ref/0]).

-ifdef(TEST).
-export([advance_seq/2, next_seq/1, process_acks/3, wrap_query_error/3]).
-endif.

%% --- Types ---

-type server_ref() :: pid() | atom().

-type state() :: #{
    socket := socket:socket(),
    socket_mod := module(),
    seq := non_neg_integer()
}.

%% --- Constants ---

-define(RECV_TIMEOUT, 5000).
-define(DUMP_RECV_TIMEOUT, 30000).
-define(NLMSG_ERROR, 2).

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

Builds the reset query and reads the response through the shared
Netlink socket. Safe to call from any process.
""".
-spec get_counter_reset(server_ref(), 0..255, binary(), binary()) ->
    {ok, map()} | {error, term()}.
get_counter_reset(Server, Family, Table, Name) ->
    gen_server:call(Server, {get_counter_reset, Family, Table, Name}, ?RECV_TIMEOUT + 2000).

-doc "List elements of a named set via netlink GET.".
-spec list_set_elems(server_ref(), 0..255, binary(), binary()) ->
    {ok, [binary()]} | {error, term()}.
list_set_elems(Server, Family, Table, SetName) ->
    gen_server:call(Server, {list_set_elems, Family, Table, SetName}, ?DUMP_RECV_TIMEOUT + 2000).

-doc "List chains in a table via netlink GET.".
-spec list_chains(server_ref(), 0..255, binary()) ->
    {ok, [map()]} | {error, term()}.
list_chains(Server, Family, Table) ->
    gen_server:call(Server, {list_chains, Family, Table}, ?DUMP_RECV_TIMEOUT + 2000).

-doc "Get full ruleset for a family via netlink GET.".
-spec get_ruleset(server_ref(), 0..255) ->
    {ok, [map()]} | {error, term()}.
get_ruleset(Server, Family) ->
    gen_server:call(Server, {get_ruleset, Family}, ?DUMP_RECV_TIMEOUT + 2000).

-doc "Stop the server.".
-spec stop(server_ref()) -> ok.
stop(Server) ->
    gen_server:stop(Server).

%% --- gen_server callbacks ---

-spec init(list()) -> {ok, state()} | {stop, term()}.
init(Opts) ->
    proc_lib:set_label(nfnl_server),
    SocketMod = proplists:get_value(socket_mod, Opts, nfnl_socket),
    OpenResult =
        case proplists:get_value(socket, Opts, undefined) of
            undefined -> SocketMod:open();
            InjectedSock -> {ok, InjectedSock}
        end,
    case OpenResult of
        {ok, Sock} ->
            Seq = erlang:system_time(second) band 16#FFFFFFFF,
            {ok, #{socket => Sock, socket_mod => SocketMod, seq => Seq}};
        {error, Reason} ->
            {stop, nft_error(socket_open_failed, #{reason => Reason})}
    end.

-spec handle_call(term(), {pid(), term()}, state()) ->
    {reply, term(), state()}.
handle_call({apply_msgs, MsgFuns}, _From,
            #{socket := Sock, socket_mod := SocketMod, seq := Seq} = State) ->
    drain_stale(Sock, SocketMod),
    FirstMsgSeq = next_seq(Seq),
    {Msgs, MsgSeqs, LastMsgSeq} = build_msgs(MsgFuns, FirstMsgSeq, [], []),
    BatchBeginSeq = Seq,
    BatchEndSeq = next_seq(LastMsgSeq),
    Batch = nft_batch:wrap(Msgs, BatchBeginSeq),
    %% Expected: only the message seqs (batch_begin/end have no NLM_F_ACK)
    Expected = maps:from_keys(MsgSeqs, true),
    Result =
        case SocketMod:send(Sock, Batch) of
            ok ->
                collect_until_seq(Sock, SocketMod, Expected, ok);
            {error, Reason} ->
                {error, nft_error(netlink_send_failed, #{reason => Reason,
                                                         batch_bytes => byte_size(Batch)})}
        end,
    NextSeq =
        case Result of
            {error, #{reason := netlink_send_failed}} ->
                %% A send error can still race with kernel-side acceptance
                %% of part of the datagram. Leave a gap so late ACKs cannot
                %% collide with the next caller's message sequence range.
                advance_seq(BatchEndSeq, length(MsgFuns));
            _ ->
                BatchEndSeq
        end,
    {reply, Result, State#{seq => NextSeq}};
handle_call({get_counter, Family, Table, Name}, _From,
            #{socket := Sock, socket_mod := SocketMod, seq := Seq} = State) ->
    drain_stale(Sock, SocketMod),
    QuerySeq = next_seq(Seq),
    Msg = nft_object:counter_get_msg(Family, Table, Name, QuerySeq),
    Result = wrap_query_error(
        counter_query_failed,
        counter_query(Sock, SocketMod, Msg, QuerySeq),
        #{family => Family, table => Table, name => Name, seq => QuerySeq}),
    {reply, Result, State#{seq => next_seq(QuerySeq)}};
handle_call({get_counter_reset, Family, Table, Name}, _From,
            #{socket := Sock, socket_mod := SocketMod, seq := Seq} = State) ->
    drain_stale(Sock, SocketMod),
    QuerySeq = next_seq(Seq),
    Msg = nft_object:counter_get_reset_msg(Family, Table, Name, QuerySeq),
    Result = wrap_query_error(
        counter_query_failed,
        counter_query(Sock, SocketMod, Msg, QuerySeq),
        #{family => Family, table => Table, name => Name, seq => QuerySeq,
          reset => true}),
    {reply, Result, State#{seq => next_seq(QuerySeq)}};
handle_call({list_set_elems, Family, Table, SetName}, _From,
            #{socket := Sock, socket_mod := SocketMod, seq := Seq} = State) ->
    drain_stale(Sock, SocketMod),
    QuerySeq = next_seq(Seq),
    Result = wrap_query_error(
        list_set_elems_failed,
        nft_query:list_set_elems(Sock, SocketMod, Family, Table, SetName, QuerySeq),
        #{family => Family, table => Table, set => SetName, seq => QuerySeq}),
    {reply, Result, State#{seq => next_seq(QuerySeq)}};
handle_call({list_chains, Family, Table}, _From,
            #{socket := Sock, socket_mod := SocketMod, seq := Seq} = State) ->
    drain_stale(Sock, SocketMod),
    QuerySeq = next_seq(Seq),
    Result = wrap_query_error(
        list_chains_failed,
        nft_query:list_chains(Sock, SocketMod, Family, Table, QuerySeq),
        #{family => Family, table => Table, seq => QuerySeq}),
    {reply, Result, State#{seq => next_seq(QuerySeq)}};
handle_call({get_ruleset, Family}, _From,
            #{socket := Sock, socket_mod := SocketMod, seq := Seq} = State) ->
    drain_stale(Sock, SocketMod),
    QuerySeq = next_seq(Seq),
    Result = wrap_query_error(
        ruleset_query_failed,
        nft_query:get_ruleset(Sock, SocketMod, Family, QuerySeq),
        #{family => Family, seq => QuerySeq}),
    {reply, Result, State#{seq => next_seq(QuerySeq)}};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, #{socket := Sock, socket_mod := SocketMod}) ->
    SocketMod:close(Sock).

%% --- Internal ---

%% Drain any messages left over in the socket's receive buffer by a
%% previous operation that didn't read them all (e.g. an apply_msgs
%% timeout with ACKs still in flight). Uses a zero-ms timeout so this
%% is essentially free when the buffer is empty.
%%
%% Without this, query paths (get_counter, list_chains, ...) would
%% consume stale responses and parse them as their own — a single
%% skipped ACK cascades because every subsequent query then reads
%% data intended for the previous call, in perpetuity until the
%% socket is closed.
-spec drain_stale(socket:socket(), module()) -> ok.
drain_stale(Sock, SocketMod) ->
    drain_stale(Sock, SocketMod, 0).

-spec drain_stale(socket:socket(), module(), non_neg_integer()) -> ok.
drain_stale(Sock, SocketMod, Count) ->
    case SocketMod:recv(Sock, 0) of
        {ok, _Stale} ->
            drain_stale(Sock, SocketMod, Count + 1);
        {error, _} when Count > 0 ->
            %% Finding stale messages here means a previous operation
            %% timed out and the kernel's late ACK landed after we
            %% gave up. Log so the operator can correlate with the
            %% earlier timeout warning.
            logger:warning("nfnl_server: discarded ~p stale netlink "
                           "message(s) from prior operation", [Count]),
            ok;
        {error, _} ->
            ok
    end.

%% 32-bit wraparound-safe sequence increment.
-spec next_seq(non_neg_integer()) -> non_neg_integer().
next_seq(Seq) -> (Seq + 1) band 16#FFFFFFFF.

-spec advance_seq(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
advance_seq(Seq, Count) when Count >= 0 ->
    (Seq + Count) band 16#FFFFFFFF.

%% Build encoded messages and collect the sequence numbers assigned.
-spec build_msgs(
    [fun((non_neg_integer()) -> binary())],
    non_neg_integer(),
    [binary()],
    [non_neg_integer()]
) ->
    {[binary()], [non_neg_integer()], non_neg_integer()}.
build_msgs([], Seq, MsgAcc, SeqAcc) ->
    %% Seq points one past the last used seq.
    %% LastUsedSeq = Seq - 1, but we return Seq as "next available" boundary.
    %% The caller needs the last actually assigned seq, so subtract 1.
    %% But with wraparound... just track it properly:
    {lists:reverse(MsgAcc), lists:reverse(SeqAcc), (Seq - 1) band 16#FFFFFFFF};
build_msgs([Fun | Rest], Seq, MsgAcc, SeqAcc) ->
    Msg = Fun(Seq),
    build_msgs(Rest, next_seq(Seq), [Msg | MsgAcc], [Seq | SeqAcc]).

%% Drain the socket until all expected sequence numbers have been seen.
%% Accumulates the first error but keeps reading — socket is guaranteed
%% clean after this function returns (no stale ACKs in the buffer).
-spec collect_until_seq(
    socket:socket(),
    module(),
    #{non_neg_integer() => true},
    ok | {error, term()}
) ->
    ok | {error, term()}.
collect_until_seq(_Sock, _SocketMod, Expected, Acc) when map_size(Expected) =:= 0 ->
    Acc;
collect_until_seq(Sock, SocketMod, Expected, Acc) ->
    case SocketMod:recv(Sock) of
        {ok, Data} ->
            case nfnl_response:parse_with_seq(Data) of
                {ok, Parsed} ->
                    {Expected2, Acc2} = process_acks(Parsed, Expected, Acc),
                    collect_until_seq(Sock, SocketMod, Expected2, Acc2);
                {error, Reason} ->
                    {error, nft_error(netlink_recv_failed, #{reason => Reason})}
            end;
        {error, timeout} ->
            %% Timeout: not all ACKs received. Return what we have.
            logger:warning("nfnl_server: timeout waiting for ~p ACKs",
                           [maps:size(Expected)]),
            case Acc of
                ok -> {error, nft_error(timeout, #{pending_acks => maps:size(Expected)})};
                Err -> Err
            end;
        {error, Reason} ->
            {error, nft_error(netlink_recv_failed, #{reason => Reason})}
    end.

%% Process parsed ACKs against the expected set.
%% Removes matched seqs from Expected, accumulates first error.
-spec process_acks(
    [nfnl_response:seq_result()],
    #{non_neg_integer() => true},
    ok | {error, term()}
) ->
    {#{non_neg_integer() => true}, ok | {error, term()}}.
process_acks([], Expected, Acc) ->
    {Expected, Acc};
process_acks([{Seq, Result} | Rest], Expected, Acc) ->
    case maps:take(Seq, Expected) of
        {true, Expected2} ->
            NewAcc = case {Acc, Result} of
                {ok, ok}           -> ok;
                {ok, {error, {Errno, ErrName}}} ->
                    {error, nft_error(batch_rejected, #{errno => Errno,
                                                        errno_name => ErrName,
                                                        seq => Seq})};
                {{error, _}, _}    -> Acc
            end,
            process_acks(Rest, Expected2, NewAcc);
        error ->
            %% Stale or out-of-band ACK — discard silently
            process_acks(Rest, Expected, Acc)
    end.

-spec counter_query(socket:socket(), module(), binary(), non_neg_integer()) ->
    {ok, map()} | {error, term()}.
counter_query(Sock, SocketMod, Msg, QuerySeq) ->
    case SocketMod:send(Sock, Msg) of
        ok ->
            case SocketMod:recv(Sock, ?RECV_TIMEOUT) of
                {ok, Data} ->
                    parse_counter_query_response(Data, QuerySeq);
                {error, timeout} ->
                    {error, timeout};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec parse_counter_query_response(binary(), non_neg_integer()) ->
    {ok, map()} | {error, term()}.
parse_counter_query_response(Data, QuerySeq) ->
    parse_counter_query_messages(Data, QuerySeq, false).

-spec parse_counter_query_messages(binary(), non_neg_integer(), boolean()) ->
    {ok, map()} | {error, term()}.
parse_counter_query_messages(<<>>, _QuerySeq, true) ->
    {error, no_counter_payload};
parse_counter_query_messages(<<>>, _QuerySeq, false) ->
    {error, invalid_response};
parse_counter_query_messages(
    <<Len:32/little, Type:16/little, Flags:16/little, Seq:32/little,
      Pid:32/little, Rest/binary>> = Bin,
    QuerySeq,
    AckSeen
) when Len >= 16, Len =< byte_size(Bin) ->
    PayloadLen = Len - 16,
    <<Payload:PayloadLen/binary, Tail/binary>> = Rest,
    case {Seq, Type} of
        {QuerySeq, ?NLMSG_ERROR} ->
            case Payload of
                <<0:32/signed-little, _/binary>> ->
                    parse_counter_query_messages(Tail, QuerySeq, true);
                <<Errno:32/signed-little, _/binary>> ->
                    {error, {netlink_error, Errno}};
                _ ->
                    {error, invalid_response}
            end;
        {QuerySeq, _} when (Type bsr 8) =:= ?NFNL_SUBSYS_NFTABLES ->
            Msg = <<Len:32/little, Type:16/little, Flags:16/little,
                    Seq:32/little, Pid:32/little, Payload/binary>>,
            case nft_object:parse_obj_response(Msg) of
                {ok, #{packets := _, bytes := _} = Counter} ->
                    {ok, Counter};
                {ok, _} ->
                    {error, invalid_response};
                {error, _} = Err ->
                    Err
            end;
        _OtherSeqOrType ->
            parse_counter_query_messages(Tail, QuerySeq, AckSeen)
    end;
parse_counter_query_messages(_Malformed, _QuerySeq, _AckSeen) ->
    {error, invalid_response}.

nft_error(socket_open_failed, Data) ->
    ?EK_ERROR(nft, socket_open_failed,
              "nf_tables netlink socket could not be opened", Data);
nft_error(netlink_send_failed, Data) ->
    ?EK_ERROR(nft, netlink_send_failed,
              "nf_tables netlink batch could not be sent", Data);
nft_error(timeout, Data) ->
    ?EK_ERROR(nft, timeout,
              "nf_tables netlink ACK wait timed out", Data);
nft_error(netlink_recv_failed, Data) ->
    ?EK_ERROR(nft, netlink_recv_failed,
              "nf_tables netlink response could not be received", Data);
nft_error(batch_rejected, Data) ->
    ?EK_ERROR(nft, batch_rejected,
              "kernel rejected nf_tables batch", Data);
nft_error(counter_query_failed, Data) ->
    ?EK_ERROR(nft, counter_query_failed,
              "nf_tables counter query failed", Data);
nft_error(list_set_elems_failed, Data) ->
    ?EK_ERROR(nft, list_set_elems_failed,
              "nf_tables set element query failed", Data);
nft_error(list_chains_failed, Data) ->
    ?EK_ERROR(nft, list_chains_failed,
              "nf_tables chain listing failed", Data);
nft_error(ruleset_query_failed, Data) ->
    ?EK_ERROR(nft, ruleset_query_failed,
              "nf_tables ruleset query failed", Data).

wrap_query_error(_Reason, {ok, _} = Ok, _Data) ->
    Ok;
wrap_query_error(counter_query_failed, {error, Reason}, Data) ->
    {error, nft_error(counter_query_failed, Data#{reason => Reason})};
wrap_query_error(list_set_elems_failed, {error, Reason}, Data) ->
    {error, nft_error(list_set_elems_failed, Data#{reason => Reason})};
wrap_query_error(list_chains_failed, {error, Reason}, Data) ->
    {error, nft_error(list_chains_failed, Data#{reason => Reason})};
wrap_query_error(ruleset_query_failed, {error, Reason}, Data) ->
    {error, nft_error(ruleset_query_failed, Data#{reason => Reason})}.
