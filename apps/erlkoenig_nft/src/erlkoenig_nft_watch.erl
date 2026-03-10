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

-module(erlkoenig_nft_watch).
-moduledoc """
Periodic counter monitor with rate calculation and event emission.

Polls named nf_tables counters at a configurable interval, calculates
packet/byte rates, and emits events when thresholds are exceeded.

Uses get_counter_reset for atomic reads — each poll gets the exact
delta since the last poll, with no race conditions.

Events are broadcast via pg (process groups). Any process can
subscribe to counter events:

    pg:join(erlkoenig_nft, counter_events, self())

    receive
        {counter_event, Name, Data} -> ...
    end

Event data:
    #{
        name     => <<"ssh_pkts">>,
        packets  => 42,
        bytes    => 3360,
        pps      => 14.0,
        bps      => 1120.0,
        interval => 2000
    }

Threshold events:
    {threshold_event, Name, Metric, Value, Threshold}
""".

-behaviour(gen_server).

-export([start_link/1,
         add_threshold/5,
         remove_threshold/2,
         get_rates/1,
         get_rates/2,
         stop/1]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2]).

%% --- Types ---

-type threshold_id() :: term().

-type config() :: #{
    family   := 0..255,
    table    := binary(),
    counters := [binary()],
    interval => pos_integer()
}.

-type state() :: #{
    config     := config(),
    socket     := socket:socket(),
    rates      := #{binary() => map()},
    thresholds := [map()],
    timer_ref  := reference() | undefined
}.

%% --- Constants ---

-define(DEFAULT_INTERVAL, 2000).

%% --- Public API ---

-doc """
Start the counter watcher.

Config:
    #{
        family   => 1,
        table    => <<"fw">>,
        counters => [<<"ssh_pkts">>, <<"dropped">>],
        interval => 2000
    }
""".
-spec start_link(config()) -> {ok, pid()} | {error, term()}.
start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

-doc """
Add a threshold that triggers when a metric exceeds a value.

Example:
    erlkoenig_nft_watch:add_threshold(Pid, ssh_alert,
        <<"ssh_pkts">>, pps,
        {fun(Name, _, Val, _) ->
            logger:warning("SSH flood: ~s at ~.1f pps", [Name, Val])
        end, '>', 100.0})
""".
-spec add_threshold(pid(), threshold_id(), binary(), atom(),
                    {fun(), atom(), number()}) -> ok.
add_threshold(Pid, Id, Counter, Metric, {Action, Op, Value}) ->
    gen_server:call(Pid, {add_threshold, #{
        id => Id,
        counter => Counter,
        metric => Metric,
        op => Op,
        value => Value,
        action => Action
    }}).

-doc "Remove a threshold by ID.".
-spec remove_threshold(pid(), threshold_id()) -> ok.
remove_threshold(Pid, Id) ->
    gen_server:call(Pid, {remove_threshold, Id}).

-doc "Get current rates for all watched counters.".
-spec get_rates(pid()) -> #{binary() => map()}.
get_rates(Pid) ->
    gen_server:call(Pid, get_rates).

-doc "Get current rate for a specific counter.".
-spec get_rates(pid(), binary()) -> map() | undefined.
get_rates(Pid, CounterName) ->
    gen_server:call(Pid, {get_rates, CounterName}).

-doc "Stop the watcher.".
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% --- gen_server callbacks ---

-spec init(config()) -> {ok, state()} | {stop, term()}.
init(Config) ->
    _ = (try pg:start_link(erlkoenig_nft) catch exit:{already_started, _} -> ok end),

    case nfnl_socket:open() of
        {ok, Sock} ->
            Interval = maps:get(interval, Config, ?DEFAULT_INTERVAL),
            TimerRef = erlang:send_after(Interval, self(), poll),
            {ok, #{
                config => Config,
                socket => Sock,
                rates => #{},
                thresholds => [],
                timer_ref => TimerRef
            }};
        {error, Reason} ->
            {stop, {socket_open_failed, Reason}}
    end.

-spec handle_call(term(), {pid(), term()}, state()) ->
    {reply, term(), state()}.
handle_call({add_threshold, T}, _From, #{thresholds := Ts} = State) ->
    {reply, ok, State#{thresholds => [T | Ts]}};
handle_call({remove_threshold, Id}, _From, #{thresholds := Ts} = State) ->
    NewTs = [T || T = #{id := TId} <- Ts, TId =/= Id],
    {reply, ok, State#{thresholds => NewTs}};
handle_call(get_rates, _From, #{rates := Rates} = State) ->
    {reply, Rates, State};
handle_call({get_rates, Name}, _From, #{rates := Rates} = State) ->
    {reply, maps:get(Name, Rates, undefined), State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(poll, #{config := Config, socket := Sock,
                    thresholds := Ts} = State) ->
    Family   = maps:get(family, Config),
    Table    = maps:get(table, Config),
    Counters = maps:get(counters, Config),
    Interval = maps:get(interval, Config, ?DEFAULT_INTERVAL),

    NewRates = lists:foldl(fun(Name, Acc) ->
        case nft_object:get_counter_reset(Sock, Family, Table, Name) of
            {ok, #{packets := Pkts, bytes := Bytes}} ->
                IntervalSec = Interval / 1000.0,
                Rate = #{
                    name     => Name,
                    packets  => Pkts,
                    bytes    => Bytes,
                    pps      => Pkts / IntervalSec,
                    bps      => Bytes / IntervalSec,
                    interval => Interval
                },
                broadcast({counter_event, Name, Rate}),
                Acc#{Name => Rate};
            {error, _} ->
                Acc
        end
    end, #{}, Counters),

    check_thresholds(Ts, NewRates),

    TimerRef = erlang:send_after(Interval, self(), poll),
    {noreply, State#{rates => NewRates, timer_ref => TimerRef}};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, #{socket := Sock, timer_ref := Ref}) ->
    _ = case Ref of
        undefined -> ok;
        _ -> _ = erlang:cancel_timer(Ref)
    end,
    nfnl_socket:close(Sock).

%% --- Internal ---

-spec broadcast(term()) -> ok.
broadcast(Msg) ->
    try
        Members = pg:get_members(erlkoenig_nft, counter_events),
        _ = [Pid ! Msg || Pid <- Members],
        ok
    catch
        _:_ -> ok
    end.

-spec check_thresholds([map()], #{binary() => map()}) -> ok.
check_thresholds([], _Rates) ->
    ok;
check_thresholds([#{counter := Name, metric := Metric,
                    op := Op, value := ThreshVal,
                    action := Action} | Rest], Rates) ->
    case maps:get(Name, Rates, undefined) of
        undefined ->
            ok;
        Rate ->
            CurrentVal = maps:get(Metric, Rate, 0),
            case eval_op(Op, CurrentVal, ThreshVal) of
                true ->
                    try Action(Name, Metric, CurrentVal, ThreshVal)
                    catch C:R -> logger:warning("[erlkoenig_nft_watch] threshold action failed: ~p:~p", [C, R]) end,
                    broadcast({threshold_event, Name, Metric,
                               CurrentVal, ThreshVal});
                false ->
                    ok
            end
    end,
    check_thresholds(Rest, Rates).

-spec eval_op(atom(), number(), number()) -> boolean().
eval_op('>', A, B)  -> A > B;
eval_op('<', A, B)  -> A < B;
eval_op('>=', A, B) -> A >= B;
eval_op('<=', A, B) -> A =< B;
eval_op('==', A, B) -> A == B.
