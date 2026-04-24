%%%-------------------------------------------------------------------
%%% @doc EUnit tests for erlkoenig_log_publisher.
%%%
%%% Pins the in_flight counter invariant: every cast that reaches
%%% handle_cast/2 must decrement the atomics counter exactly once,
%%% regardless of whether the chunk gets buffered, coalesced, queued,
%%% dropped (channel filter), drop-oldest'd (queue full), or
%%% published. Without this invariant the level-1 admission control
%%% in erlkoenig_ct:forward_output/3 drifts toward LOG_HIGH_WATERMARK
%%% and eventually drops every subsequent chunk.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_log_publisher_tests).

-include_lib("eunit/include/eunit.hrl").

%% Start the publisher directly (no AMQP — it will run in the
%% "disconnected" branch, which is exactly what the unit test wants).
%% The publisher also calls erlkoenig_events:notify/1 on drop/disconnect,
%% so we make sure that gen_event manager is alive for the test. If it
%% already exists (e.g. from a prior test), we reuse it.
start_publisher(Channels) ->
    ensure_events(),
    InFlight = atomics:new(1, [{signed, false}]),
    ContainerId = <<"test-container-id-12345">>,
    ContainerName = <<"test_ct">>,
    {ok, Pid} = erlkoenig_log_publisher:start_link(
        ContainerId, ContainerName, Channels, 1, InFlight),
    {Pid, InFlight}.

ensure_events() ->
    case whereis(erlkoenig_events) of
        undefined ->
            {ok, _} = erlkoenig_events:start_link(),
            ok;
        _ ->
            ok
    end.

stop_publisher(Pid) ->
    try erlkoenig_log_publisher:stop(Pid) catch _:_ -> ok end.

%% sync_cast — send a cast then do a call to make sure the cast
%% was processed before we observe the counter. (Call is serialised
%% behind the cast in the gen_server mailbox.)
sync(Pid) ->
    %% use a cast that lands in the catch-all handle_cast clause,
    %% then a call that replies {error, not_supported} — either is
    %% enough to confirm all prior casts have been processed.
    _ = gen_server:call(Pid, ping, 5000),
    ok.

simulate_forward(Pid, InFlight, Stream, Chunk) ->
    %% Mirror erlkoenig_ct:forward_output/3: increment in_flight,
    %% then cast.
    atomics:add(InFlight, 1, 1),
    gen_server:cast(Pid, {log, Stream, Chunk}).

%% =====================================================================
%% Tests
%% =====================================================================

in_flight_balanced_on_single_chunk_test() ->
    {Pid, InFlight} = start_publisher([stdout]),
    simulate_forward(Pid, InFlight, stdout, <<"hello\n">>),
    sync(Pid),
    ?assertEqual(0, atomics:get(InFlight, 1)),
    stop_publisher(Pid).

in_flight_balanced_on_many_coalesced_chunks_test() ->
    %% Regression guard for the MAIN bug: many small chunks coalesce
    %% into a single queued iolist. In the old code that released 1
    %% slot on drain instead of the N expected. Counter drifted up.
    {Pid, InFlight} = start_publisher([stdout]),
    N = 50,
    lists:foreach(fun(_) ->
        simulate_forward(Pid, InFlight, stdout, <<"small\n">>)
    end, lists:seq(1, N)),
    sync(Pid),
    ?assertEqual(0, atomics:get(InFlight, 1)),
    stop_publisher(Pid).

in_flight_balanced_on_channel_filter_drop_test() ->
    %% Channel filter: publisher is configured for stdout only, but
    %% stderr casts still need to decrement their in_flight slot.
    {Pid, InFlight} = start_publisher([stdout]),
    simulate_forward(Pid, InFlight, stderr, <<"ignored\n">>),
    simulate_forward(Pid, InFlight, stderr, <<"also ignored\n">>),
    sync(Pid),
    ?assertEqual(0, atomics:get(InFlight, 1)),
    stop_publisher(Pid).

in_flight_balanced_on_queue_full_drop_test() ->
    %% When the bounded publish queue overflows, enqueue_chunk's
    %% drop-oldest branch used to discard the old chunk without
    %% releasing its in_flight slot. With the fix, in_flight is
    %% decremented at cast-receive so drop-oldest is counter-neutral
    %% on the in_flight side — ONLY the dropped_count metric moves.
    %%
    %% To actually overflow the queue we need to cross the 4KB
    %% buffer threshold many times while the publisher is
    %% disconnected (so drain can't keep up). max_queue_len is 1000
    %% so we need >1000 flushes. Each 4KB chunk triggers an
    %% immediate flush in buffer_stdout.
    {Pid, InFlight} = start_publisher([stdout]),
    BigChunk = binary:copy(<<"x">>, 5000),  %% >= CHUNK_SIZE → immediate flush
    N = 1100,
    lists:foreach(fun(_) ->
        simulate_forward(Pid, InFlight, stdout, BigChunk)
    end, lists:seq(1, N)),
    sync(Pid),
    ?assertEqual(0, atomics:get(InFlight, 1)),
    stop_publisher(Pid).

in_flight_balanced_mixed_streams_test() ->
    %% Interleave stdout and stderr on a publisher subscribed to both.
    {Pid, InFlight} = start_publisher([stdout, stderr]),
    lists:foreach(fun(I) ->
        Stream = case I rem 2 of 0 -> stdout; 1 -> stderr end,
        simulate_forward(Pid, InFlight, Stream,
                         iolist_to_binary([<<"line ">>, integer_to_binary(I), <<"\n">>]))
    end, lists:seq(1, 40)),
    sync(Pid),
    ?assertEqual(0, atomics:get(InFlight, 1)),
    stop_publisher(Pid).
