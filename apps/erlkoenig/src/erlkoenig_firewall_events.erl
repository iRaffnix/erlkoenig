%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_firewall_events).
-moduledoc """
Node-local canonical firewall event bus.

The process subscribes to the native Erlkoenig nft/guard pg groups,
normalizes low-level messages through `erlkoenig_firewall_event`, and
keeps a bounded in-memory history for operator tools. It deliberately
does not mutate nftables. Enforcement remains owned by the threat mesh;
this module is read-side plumbing for CLI, dashboards, AMQP bridges,
and ontology explanation consumers.
""".

-behaviour(gen_server).

-export([start_link/0]).
-export([ingest/1, recent/1, since/3, stats/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(DEFAULT_MAX_EVENTS, 1024).
-define(GROUPS, [nflog_events, counter_events, ct_guard_events]).

-type event() :: map().
-type cursor() :: non_neg_integer().

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc "Inject one raw or canonical event. Intended for tests and internal adapters.".
-spec ingest(term()) -> ok.
ingest(Msg) ->
    gen_server:cast(?MODULE, {ingest, Msg}).

-doc "Return the newest `Limit` canonical events, oldest first.".
-spec recent(pos_integer()) -> {ok, [event()]} | {error, not_running}.
recent(Limit) when is_integer(Limit), Limit > 0 ->
    call_if_running({recent, Limit}).

-doc "Return event-buffer health and cursor information.".
-spec stats() -> {ok, map()} | {error, not_running}.
stats() ->
    call_if_running(stats).

-doc """
Return events with `seq > Cursor`.

`TimeoutMs = 0` is a plain snapshot. A positive timeout long-polls until
at least one newer event arrives or the timeout expires.
""".
-spec since(cursor(), non_neg_integer(), pos_integer()) ->
    {ok, cursor(), [event()]} | {error, not_running}.
since(Cursor, TimeoutMs, Limit)
  when is_integer(Cursor), Cursor >= 0,
       is_integer(TimeoutMs), TimeoutMs >= 0,
       is_integer(Limit), Limit > 0 ->
    call_if_running({since, Cursor, TimeoutMs, Limit}, TimeoutMs + 5000).

init([]) ->
    join_groups(),
    MaxEvents = application:get_env(erlkoenig, firewall_event_buffer,
                                    ?DEFAULT_MAX_EVENTS),
    {ok, #{seq => 0,
           events => [],
           max_events => MaxEvents,
           waiters => []}}.

handle_call({recent, Limit}, _From, State) ->
    {reply, {ok, newest(Limit, maps:get(events, State))}, State};
handle_call(stats, _From, State) ->
    {reply, {ok, #{
        running => true,
        cursor => maps:get(seq, State),
        buffered => length(maps:get(events, State)),
        max_events => maps:get(max_events, State),
        waiting_clients => length(maps:get(waiters, State)),
        groups => ?GROUPS
    }}, State};
handle_call({since, Cursor, 0, Limit}, _From, State) ->
    Events = after_cursor(Cursor, Limit, maps:get(events, State)),
    {reply, {ok, maps:get(seq, State), Events}, State};
handle_call({since, Cursor, TimeoutMs, Limit}, From, State) ->
    Events = after_cursor(Cursor, Limit, maps:get(events, State)),
    case Events of
        [] ->
            Ref = erlang:send_after(TimeoutMs, self(), {waiter_timeout, From}),
            Waiter = #{from => From, cursor => Cursor, limit => Limit, timer => Ref},
            {noreply, State#{waiters => [Waiter | maps:get(waiters, State)]}};
        _ ->
            {reply, {ok, maps:get(seq, State), Events}, State}
    end;
handle_call(_Msg, _From, State) ->
    {reply, {error, badarg}, State}.

handle_cast({ingest, Msg}, State) ->
    {noreply, maybe_store(Msg, State)};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({waiter_timeout, From}, State) ->
    {Waiter, Rest} = take_waiter(From, maps:get(waiters, State)),
    case Waiter of
        undefined ->
            {noreply, State};
        #{cursor := Cursor} ->
            gen_server:reply(From, {ok, maps:get(seq, State),
                                    after_cursor(Cursor, 0, maps:get(events, State))}),
            {noreply, State#{waiters => Rest}}
    end;
handle_info(Msg, State) ->
    {noreply, maybe_store(Msg, State)}.

terminate(_Reason, _State) ->
    leave_groups(),
    ok.

call_if_running(Request) ->
    call_if_running(Request, 5000).

call_if_running(Request, Timeout) ->
    case whereis(?MODULE) of
        undefined -> {error, not_running};
        _Pid      -> gen_server:call(?MODULE, Request, Timeout)
    end.

maybe_store(Msg, State) ->
    case erlkoenig_firewall_event:normalize(Msg) of
        {ok, Event0} ->
            Seq = maps:get(seq, State) + 1,
            Event = Event0#{seq => Seq},
            Events = trim([Event | maps:get(events, State)],
                          maps:get(max_events, State)),
            State1 = State#{seq => Seq, events => Events},
            notify_waiters(State1);
        skip ->
            State
    end.

notify_waiters(State) ->
    Events = maps:get(events, State),
    Seq = maps:get(seq, State),
    {Pending, Done} =
        lists:partition(
          fun(#{cursor := Cursor}) ->
              after_cursor(Cursor, 1, Events) =:= []
          end,
          maps:get(waiters, State)),
    lists:foreach(
      fun(#{from := From, cursor := Cursor, limit := Limit, timer := Timer}) ->
          erlang:cancel_timer(Timer),
          gen_server:reply(From, {ok, Seq, after_cursor(Cursor, Limit, Events)})
      end, Done),
    State#{waiters => Pending}.

newest(Limit, EventsNewestFirst) ->
    lists:reverse(lists:sublist(EventsNewestFirst, Limit)).

after_cursor(Cursor, Limit, EventsNewestFirst) ->
    Matches = lists:reverse([E || #{seq := Seq} = E <- EventsNewestFirst,
                                    Seq > Cursor]),
    case Limit of
        0 -> [];
        _ -> lists:sublist(Matches, Limit)
    end.

trim(Events, Max) when is_integer(Max), Max > 0 ->
    lists:sublist(Events, Max);
trim(Events, _Max) ->
    lists:sublist(Events, ?DEFAULT_MAX_EVENTS).

take_waiter(From, Waiters) ->
    take_waiter(From, Waiters, []).

take_waiter(_From, [], Acc) ->
    {undefined, lists:reverse(Acc)};
take_waiter(From, [#{from := From} = W | Rest], Acc) ->
    {W, lists:reverse(Acc) ++ Rest};
take_waiter(From, [W | Rest], Acc) ->
    take_waiter(From, Rest, [W | Acc]).

join_groups() ->
    lists:foreach(fun(Group) ->
        catch pg:join(erlkoenig_nft, Group, self())
    end, ?GROUPS).

leave_groups() ->
    lists:foreach(fun(Group) ->
        catch pg:leave(erlkoenig_nft, Group, self())
    end, ?GROUPS).
