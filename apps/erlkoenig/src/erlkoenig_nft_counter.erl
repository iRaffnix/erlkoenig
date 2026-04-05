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

-module(erlkoenig_nft_counter).
-moduledoc """
Per-counter watcher process.

Each instance monitors a single named nf_tables counter. Uses
non-destructive reads (get_counter, not get_counter_reset) so the
kernel counters keep their cumulative values visible in
`nft list ruleset`.

Computes rates (pps/bps) from the delta between consecutive polls.

Events broadcast to the `counter_events` pg group:

    {counter_event, Name, #{
        name     => <<"ssh">>,
        packets  => 42,         %% delta since last poll
        bytes    => 3360,       %% delta since last poll
        total_packets => 1000,  %% cumulative kernel value
        total_bytes   => 80000, %% cumulative kernel value
        pps      => 21.0,
        bps      => 1680.0,
        interval => 2000
    }}

Threshold alerts:

    {threshold_event, Id, Name, Metric, Value, Threshold}
""".

-behaviour(gen_server).

-export([start_link/1]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

%% --- Types ---

-type threshold() :: #{
    id := term(),
    metric := pps | bps,
    op := '>' | '<' | '>=' | '<=' | '==',
    value := number(),
    action := fun()
}.

-type state() :: #{
    name := binary(),
    family := 0..255,
    table := binary(),
    interval := pos_integer(),
    thresholds := [threshold()],
    timer_ref := reference() | undefined,
    prev_pkts := non_neg_integer(),
    prev_bytes := non_neg_integer(),
    last_rate := map(),
    history := [float()]
}.

-define(HISTORY_LEN, 20).

%% --- Constants ---

-define(DEFAULT_INTERVAL, 2000).

%% --- Public API ---

-doc "Start a counter watcher.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

%% --- gen_server callbacks ---

-spec init(map()) -> {ok, state()}.
init(Config) ->
    Name = maps:get(name, Config),
    Family = maps:get(family, Config),
    Table = maps:get(table, Config),
    Interval = maps:get(interval, Config, ?DEFAULT_INTERVAL),
    Thresholds = maps:get(thresholds, Config, []),

    %% Do an initial read to set the baseline
    {PrevPkts, PrevBytes} =
        case nfnl_server:get_counter(erlkoenig_nft_srv, Family, Table, Name) of
            {ok, #{packets := P, bytes := B}} -> {P, B};
            _ -> {0, 0}
        end,

    TimerRef = erlang:send_after(Interval, self(), poll),

    {ok, #{
        name => Name,
        family => Family,
        table => Table,
        interval => Interval,
        thresholds => Thresholds,
        timer_ref => TimerRef,
        prev_pkts => PrevPkts,
        prev_bytes => PrevBytes,
        last_rate => #{
            name => Name,
            packets => 0,
            bytes => 0,
            total_packets => PrevPkts,
            total_bytes => PrevBytes,
            pps => 0.0,
            bps => 0.0,
            interval => Interval,
            history => []
        },
        history => []
    }}.

-spec handle_call(term(), {pid(), term()}, state()) ->
    {reply, term(), state()}.
handle_call(get_rates, _From, State) ->
    {reply, maps:get(last_rate, State), State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(
    poll,
    #{
        name := Name,
        family := Family,
        table := Table,
        interval := Interval,
        thresholds := Thresholds,
        prev_pkts := PrevPkts,
        prev_bytes := PrevBytes,
        history := History
    } = State
) ->
    case nfnl_server:get_counter(erlkoenig_nft_srv, Family, Table, Name) of
        {ok, #{packets := CurPkts, bytes := CurBytes}} ->
            %% Delta since last poll
            DeltaPkts = max(0, CurPkts - PrevPkts),
            DeltaBytes = max(0, CurBytes - PrevBytes),
            IntervalSec = Interval / 1000.0,
            Pps = DeltaPkts / IntervalSec,
            NewHistory = lists:sublist([Pps | History], ?HISTORY_LEN),
            Rate = #{
                name => Name,
                packets => DeltaPkts,
                bytes => DeltaBytes,
                total_packets => CurPkts,
                total_bytes => CurBytes,
                pps => Pps,
                bps => DeltaBytes / IntervalSec,
                interval => Interval,
                history => lists:reverse(NewHistory)
            },
            erlkoenig_nft_events:notify_counter_event({counter_event, Name, Rate}),
            check_thresholds(Name, Thresholds, Rate),
            TimerRef = erlang:send_after(Interval, self(), poll),
            {noreply, State#{
                timer_ref => TimerRef,
                prev_pkts => CurPkts,
                prev_bytes => CurBytes,
                last_rate => Rate,
                history => NewHistory
            }};
        {error, Reason} ->
            logger:warning("[erlkoenig_nft_counter:~s] poll failed: ~p", [Name, Reason]),
            TimerRef = erlang:send_after(Interval, self(), poll),
            {noreply, State#{timer_ref => TimerRef}}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, #{timer_ref := Ref}) ->
    case Ref of
        undefined ->
            ok;
        _ ->
            _ = erlang:cancel_timer(Ref),
            ok
    end,
    ok.

%% --- Internal ---

-spec check_thresholds(binary(), [threshold()], map()) -> ok.
check_thresholds(_Name, [], _Rate) ->
    ok;
check_thresholds(
    Name,
    [
        #{
            metric := Metric,
            op := Op,
            value := ThreshVal,
            action := Action
        } = T
        | Rest
    ],
    Rate
) ->
    CurrentVal = maps:get(Metric, Rate, 0),
    case eval_op(Op, CurrentVal, ThreshVal) of
        true ->
            Id = maps:get(id, T, undefined),
            try
                Action(Name, Metric, CurrentVal, ThreshVal)
            catch
                C:R ->
                    logger:warning("[erlkoenig_nft_counter] threshold action failed: ~p:~p", [C, R])
            end,
            erlkoenig_nft_events:notify_counter_event(
                {threshold_event, Id, Name, Metric, CurrentVal, ThreshVal}
            );
        false ->
            ok
    end,
    check_thresholds(Name, Rest, Rate).

-spec eval_op(atom(), number(), number()) -> boolean().
eval_op('>', A, B) -> A > B;
eval_op('<', A, B) -> A < B;
eval_op('>=', A, B) -> A >= B;
eval_op('<=', A, B) -> A =< B;
eval_op('==', A, B) -> A == B.
