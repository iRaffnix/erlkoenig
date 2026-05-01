-module(nfnl_mock_socket).
-behaviour(gen_server).

-export([start_link/1, drain_count/1, inject_raw_recv/2, release_late/1]).
-export([open/0, send/2, recv/1, recv/2, close/1]).
-export([init/1, handle_call/3, handle_cast/2]).

start_link(SendModes) ->
    gen_server:start_link(?MODULE, SendModes, []).

release_late(Pid) ->
    gen_server:call(Pid, release_late).

inject_raw_recv(Pid, Bin) when is_binary(Bin) ->
    gen_server:call(Pid, {inject_raw_recv, Bin}).

drain_count(Pid) ->
    gen_server:call(Pid, drain_count).

open() ->
    start_link([auto_ack]).

send(Pid, Bin) ->
    gen_server:call(Pid, {send, Bin}).

recv(Pid) ->
    recv(Pid, 5000).

recv(Pid, Timeout) ->
    gen_server:call(Pid, {recv, Timeout}).

close(Pid) ->
    gen_server:call(Pid, close).

init(SendModes) ->
    {ok, #{send_modes => SendModes, recvq => [], late => [], drain_count => 0}}.

handle_call({send, Bin}, _From, State) ->
    {Mode, RestModes} =
        case maps:get(send_modes, State) of
            [M | Rest] -> {M, Rest};
            [] -> {auto_ack, []}
        end,
    Acks = ack_batch(Bin),
    State1 = State#{send_modes => RestModes},
    case Mode of
        auto_ack ->
            {reply, ok, enqueue(Acks, State1)};
        {raw_recv, RawBin} when is_binary(RawBin) ->
            {reply, ok, enqueue([RawBin], State1)};
        no_ack ->
            {reply, ok, State1#{late => maps:get(late, State1) ++ Acks}};
        {error, Reason} ->
            {reply, {error, Reason}, State1#{late => maps:get(late, State1) ++ Acks}}
    end;
handle_call({recv, Timeout}, _From, #{recvq := [Msg | Rest]} = State) ->
    State1 =
        case Timeout of
            0 -> State#{drain_count => maps:get(drain_count, State) + 1};
            _ -> State
        end,
    {reply, {ok, Msg}, State1#{recvq => Rest}};
handle_call({recv, _Timeout}, _From, State) ->
    {reply, {error, timeout}, State};
handle_call(drain_count, _From, State) ->
    {reply, maps:get(drain_count, State), State};
handle_call(release_late, _From, #{late := Late} = State) ->
    {reply, ok, enqueue(Late, State#{late => []})};
handle_call({inject_raw_recv, Bin}, _From, State) ->
    {reply, ok, enqueue([Bin], State)};
handle_call(close, _From, State) ->
    {reply, ok, State};
handle_call(_Call, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Cast, State) ->
    {noreply, State}.

enqueue([], State) ->
    State;
enqueue(Msgs, #{recvq := Recvq} = State) ->
    State#{recvq => Recvq ++ Msgs}.

ack_batch(Bin) ->
    Seqs = parse_seqs(Bin, []),
    MidSeqs =
        case Seqs of
            [_Begin, _End] -> [];
            [_Begin | Rest] when Rest =/= [] -> lists:droplast(Rest);
            _ -> Seqs
        end,
    [ack(Seq) || Seq <- MidSeqs].

parse_seqs(<<>>, Acc) ->
    lists:reverse(Acc);
parse_seqs(<<Len:32/little, _Type:16/little, _Flags:16/little,
             Seq:32/little, _Pid:32/little, _/binary>> = Bin, Acc)
  when Len >= 16, Len =< byte_size(Bin) ->
    <<_:Len/binary, Tail/binary>> = Bin,
    parse_seqs(Tail, [Seq | Acc]);
parse_seqs(_Other, Acc) ->
    lists:reverse(Acc).

ack(Seq) ->
    <<20:32/little, 2:16/little, 0:16/little, Seq:32/little, 0:32/little,
      0:32/signed-little>>.
