%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_log_publisher).
-moduledoc """
Per-container log publisher to RabbitMQ Streams (SPEC-EK-011).

Receives stdout/stderr chunks from erlkoenig_ct:forward_output/3
and publishes them to a single RabbitMQ Stream per container.

Three-level backpressure:
  1. atomics high-watermark in forward_output (admission control)
  2. bounded queue in state (publish backlog)
  3. drop accounting (system.log.overflow events)

The pipeline is at-most-once. Container I/O is never blocked.
""".

-behaviour(gen_server).

-include_lib("amqp_client/include/amqp_client.hrl").

-export([start_link/5, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(MAX_QUEUE_LEN, 1000).
-define(STDOUT_FLUSH_MS, 100).
-define(STDERR_FLUSH_MS, 50).
-define(CHUNK_SIZE, 4096).

-record(state, {
    container_name  :: binary(),
    container_id    :: binary(),
    instance        :: binary(),
    boot            :: non_neg_integer(),
    seq             :: non_neg_integer(),
    stream_name     :: binary(),
    channels        :: [stdout | stderr],
    in_flight       :: atomics:atomics_ref(),
    %% Connection
    channel         :: pid() | undefined,
    connected       :: boolean(),
    %% Buffering
    stdout_buf      :: iolist(),
    stdout_bytes    :: non_neg_integer(),
    stderr_buf      :: iolist(),
    stderr_bytes    :: non_neg_integer(),
    flush_timer_out :: reference() | undefined,
    flush_timer_err :: reference() | undefined,
    %% Bounded publish queue
    queue           :: queue:queue(),
    queue_len       :: non_neg_integer(),
    max_queue_len   :: non_neg_integer(),
    draining        :: boolean(),
    %% Drop accounting
    dropped_count   :: non_neg_integer(),
    dropped_bytes   :: non_neg_integer()
}).

%% ===================================================================
%% API
%% ===================================================================

-spec start_link(binary(), binary(), [atom()], non_neg_integer(), atomics:atomics_ref()) ->
    {ok, pid()} | {error, term()}.
start_link(ContainerId, ContainerName, Channels, RetentionDays, InFlight) ->
    gen_server:start_link(?MODULE, {ContainerId, ContainerName, Channels, RetentionDays, InFlight}, []).

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid, normal, 5000).

%% ===================================================================
%% gen_server callbacks
%% ===================================================================

init({ContainerId, ContainerName, Channels, RetentionDays, InFlight}) ->
    proc_lib:set_label({erlkoenig_log_publisher, ContainerName}),
    Instance = binary:part(ContainerId, 0, min(8, byte_size(ContainerId))),
    StreamName = <<"erlkoenig.log.", ContainerName/binary>>,
    %% Try to connect — stream declare may fail and kill the channel,
    %% so we open a separate channel for declare, then open the publish channel.
    RetentionStr = list_to_binary(integer_to_list(RetentionDays) ++ "D"),
    DeclareOk = try
        case try_open_channel() of
            undefined -> false;
            DeclCh ->
                ensure_stream(DeclCh, StreamName, RetentionStr),
                %% Close declare channel (we'll use a separate one for publishing)
                try amqp_channel:close(DeclCh) catch _:_ -> ok end,
                true
        end
    catch _:_ -> false
    end,
    Channel = case DeclareOk of
        true -> try_open_channel();
        false ->
            erlang:send_after(5000, self(), try_reconnect),
            undefined
    end,
    Connected = Channel =/= undefined,
    {ok, #state{
        container_name = ContainerName,
        container_id = ContainerId,
        instance = Instance,
        boot = 0,
        seq = 0,
        stream_name = StreamName,
        channels = Channels,
        in_flight = InFlight,
        channel = Channel,
        connected = Connected,
        stdout_buf = [],
        stdout_bytes = 0,
        stderr_buf = [],
        stderr_bytes = 0,
        queue = queue:new(),
        queue_len = 0,
        max_queue_len = ?MAX_QUEUE_LEN,
        draining = false,
        dropped_count = 0,
        dropped_bytes = 0
    }}.

handle_call(_, _From, State) ->
    {reply, {error, not_supported}, State}.

%% --- Log ingress (from erlkoenig_ct:forward_output/3) ---

handle_cast({log, stdout, Chunk}, #state{channels = Channels} = State) ->
    case lists:member(stdout, Channels) of
        true -> {noreply, buffer_stdout(Chunk, State)};
        false ->
            atomics:sub(State#state.in_flight, 1, 1),
            {noreply, State}
    end;

handle_cast({log, stderr, Chunk}, #state{channels = Channels} = State) ->
    case lists:member(stderr, Channels) of
        true -> {noreply, buffer_stderr(Chunk, State)};
        false ->
            atomics:sub(State#state.in_flight, 1, 1),
            {noreply, State}
    end;

handle_cast(_, State) ->
    {noreply, State}.

%% --- Timers ---

handle_info(flush_stdout, State) ->
    State2 = flush_buffer(stdout, State),
    {noreply, State2#state{flush_timer_out = undefined}};

handle_info(flush_stderr, State) ->
    State2 = flush_buffer(stderr, State),
    {noreply, State2#state{flush_timer_err = undefined}};

%% --- Drain loop ---

handle_info(drain, #state{connected = false} = State) ->
    {noreply, State#state{draining = false}};

handle_info(drain, #state{queue_len = 0} = State) ->
    {noreply, State#state{draining = false}};

handle_info(drain, State) ->
    case queue:out(State#state.queue) of
        {{value, {Fd, Chunk, Seq}}, Q2} ->
            publish_chunk(Fd, Chunk, Seq, State),
            atomics:sub(State#state.in_flight, 1, 1),
            State2 = State#state{queue = Q2, queue_len = State#state.queue_len - 1},
            self() ! drain,
            {noreply, State2};
        {empty, _} ->
            {noreply, State#state{draining = false}}
    end;

%% --- Connection loss ---

handle_info({'DOWN', _Ref, process, Pid, _Reason},
            #state{channel = Pid} = State) ->
    logger:warning("erlkoenig_log_publisher ~s: channel down, reconnecting",
                   [State#state.container_name]),
    erlkoenig_events:notify({log_disconnected, State#state.container_name}),
    erlang:send_after(5000, self(), try_reconnect),
    {noreply, State#state{channel = undefined, connected = false, draining = false}};

handle_info(try_reconnect, State) ->
    case try_open_channel() of
        undefined ->
            erlang:send_after(5000, self(), try_reconnect),
            {noreply, State};
        Channel ->
            ensure_stream(Channel, State#state.stream_name, <<"90D">>),
            self() ! drain,
            {noreply, State#state{channel = Channel, connected = true}}
    end;

handle_info(_, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    %% Flush remaining buffers
    State2 = flush_buffer(stdout, State),
    State3 = flush_buffer(stderr, State2),
    %% Drain queue
    drain_all(State3),
    ok.

%% ===================================================================
%% Buffering
%% ===================================================================

buffer_stdout(Chunk, #state{stdout_buf = Buf, stdout_bytes = Bytes} = State) ->
    NewBytes = Bytes + byte_size(Chunk),
    NewBuf = [Buf, Chunk],
    if NewBytes >= ?CHUNK_SIZE ->
        State2 = flush_buffer(stdout, State#state{stdout_buf = NewBuf, stdout_bytes = NewBytes}),
        _ = cancel_timer(State2#state.flush_timer_out),
        State2#state{flush_timer_out = undefined};
       true ->
        Timer = case State#state.flush_timer_out of
            undefined -> erlang:send_after(?STDOUT_FLUSH_MS, self(), flush_stdout);
            Existing -> Existing
        end,
        State#state{stdout_buf = NewBuf, stdout_bytes = NewBytes, flush_timer_out = Timer}
    end.

buffer_stderr(Chunk, #state{stderr_buf = Buf, stderr_bytes = Bytes} = State) ->
    NewBytes = Bytes + byte_size(Chunk),
    NewBuf = [Buf, Chunk],
    %% stderr: best-effort line-aligned — flush at \n, 4KB, or timer
    HasNewline = binary:match(Chunk, <<"\n">>) =/= nomatch,
    if HasNewline orelse NewBytes >= ?CHUNK_SIZE ->
        State2 = flush_buffer(stderr, State#state{stderr_buf = NewBuf, stderr_bytes = NewBytes}),
        _ = cancel_timer(State2#state.flush_timer_err),
        State2#state{flush_timer_err = undefined};
       true ->
        Timer = case State#state.flush_timer_err of
            undefined -> erlang:send_after(?STDERR_FLUSH_MS, self(), flush_stderr);
            Existing -> Existing
        end,
        State#state{stderr_buf = NewBuf, stderr_bytes = NewBytes, flush_timer_err = Timer}
    end.

flush_buffer(stdout, #state{stdout_buf = [], stdout_bytes = 0} = State) -> State;
flush_buffer(stdout, #state{stdout_buf = Buf, stdout_bytes = _Bytes} = State) ->
    enqueue_chunk(stdout, iolist_to_binary(Buf), State#state{stdout_buf = [], stdout_bytes = 0});

flush_buffer(stderr, #state{stderr_buf = [], stderr_bytes = 0} = State) -> State;
flush_buffer(stderr, #state{stderr_buf = Buf, stderr_bytes = _Bytes} = State) ->
    enqueue_chunk(stderr, iolist_to_binary(Buf), State#state{stderr_buf = [], stderr_bytes = 0}).

%% ===================================================================
%% Bounded Queue
%% ===================================================================

enqueue_chunk(Fd, Chunk, #state{seq = Seq, queue = Q, queue_len = Len,
                                 max_queue_len = Max} = State) ->
    State2 = State#state{seq = Seq + 1},
    if Len >= Max ->
        %% Drop oldest
        {{value, {_OldFd, OldChunk, _OldSeq}}, Q2} = queue:out(Q),
        Q3 = queue:in({Fd, Chunk, Seq}, Q2),
        DroppedBytes = byte_size(OldChunk),
        notify_drop(State2, 1, DroppedBytes),
        State2#state{queue = Q3,
                     dropped_count = State2#state.dropped_count + 1,
                     dropped_bytes = State2#state.dropped_bytes + DroppedBytes};
       true ->
        Q2 = queue:in({Fd, Chunk, Seq}, Q),
        State3 = State2#state{queue = Q2, queue_len = Len + 1},
        maybe_start_drain(State3)
    end.

maybe_start_drain(#state{draining = true} = State) -> State;
maybe_start_drain(#state{connected = false} = State) -> State;
maybe_start_drain(State) ->
    self() ! drain,
    State#state{draining = true}.

%% ===================================================================
%% Publishing
%% ===================================================================

publish_chunk(Fd, Chunk, Seq, #state{channel = Channel, stream_name = StreamName} = State)
  when Channel =/= undefined ->
    Headers = [
        {<<"fd">>, longstr, atom_to_binary(Fd)},
        {<<"name">>, longstr, State#state.container_name},
        {<<"node">>, longstr, atom_to_binary(node())},
        {<<"instance">>, longstr, State#state.instance},
        {<<"seq">>, long, Seq},
        {<<"boot">>, long, State#state.boot},
        {<<"wall_ts_ms">>, long, erlang:system_time(millisecond)}
    ],
    Props = #'P_basic'{
        app_id = <<"erlkoenig">>,
        message_id = <<(State#state.container_id)/binary, ":", (integer_to_binary(Seq))/binary>>,
        type = <<"log">>,
        headers = Headers
    },
    FilterValue = atom_to_binary(Fd),
    Publish = #'basic.publish'{
        exchange = <<>>,
        routing_key = StreamName
    },
    try
        amqp_channel:cast(Channel, Publish, #amqp_msg{
            props = Props#'P_basic'{headers = [{<<"x-stream-filter-value">>, longstr, FilterValue} | Headers]},
            payload = Chunk
        })
    catch _:_ -> ok
    end;
publish_chunk(_, _, _, _) -> ok.

drain_all(#state{queue_len = 0}) -> ok;
drain_all(#state{channel = undefined}) -> ok;
drain_all(State) ->
    case queue:out(State#state.queue) of
        {{value, {Fd, Chunk, Seq}}, Q2} ->
            publish_chunk(Fd, Chunk, Seq, State),
            drain_all(State#state{queue = Q2, queue_len = State#state.queue_len - 1});
        {empty, _} -> ok
    end.

%% ===================================================================
%% Helpers
%% ===================================================================

try_open_channel() ->
    try erlkoenig_amqp_conn:open_channel() of
        {ok, Channel} ->
            erlang:monitor(process, Channel),
            Channel;
        _ -> undefined
    catch _:_ -> undefined
    end.

ensure_stream(Channel, StreamName, RetentionStr) ->
    try
        Res = amqp_channel:call(Channel, #'queue.declare'{
            queue = StreamName,
            durable = true,
            arguments = [
                {<<"x-queue-type">>, longstr, <<"stream">>},
                {<<"x-max-age">>, longstr, RetentionStr}
            ]
        }),
        logger:info("erlkoenig_log_publisher: stream ~s declared (retention=~s): ~p",
                    [StreamName, RetentionStr, Res])
    catch C:R ->
        logger:warning("erlkoenig_log_publisher: stream ~s declare failed: ~p:~p",
                       [StreamName, C, R])
    end.

notify_drop(#state{container_name = Name}, Count, Bytes) ->
    erlkoenig_events:notify({log_drop, Name, Count, Bytes}).

cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> erlang:cancel_timer(Ref).
