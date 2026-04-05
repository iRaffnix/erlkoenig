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

-module(erlkoenig_nft_otel).
-moduledoc """
OpenTelemetry extension for erlkoenig_nft.

Pure event consumer — subscribes to pg groups and translates domain
events into OTel metrics, traces, and structured logs via OTLP.

This module knows only the event language of the core. It does not
reference facade functions, facade structures, or historical call paths.

Returns `ignore` when the OpenTelemetry SDK is not loaded.

## Metrics

Creates OTel instruments on init, subscribes to `counter_events`,
`ct_events`, `nflog_events`, and `control_events` pg groups,
and polls `guard_stats/0`.

## Traces

Creates post-hoc event spans for control-plane operations
(`ban`, `unban`, `reload`, `add_element`, `del_element`).
These are event representations, NOT latency measurements.

## Logs

Emits structured log records for security-relevant events
(bans, threat alerts, NFLOG drops).
""".

-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2]).

-define(GUARD_POLL_INTERVAL, 10000).

%% --- Public API ---

-doc "Start the OTel extension server.".
-spec start_link() -> {ok, pid()} | {error, term()} | ignore.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% --- gen_server callbacks ---

init([]) ->
    proc_lib:set_label(erlkoenig_nft_otel),
    case otel_sdk_loaded() of
        true ->
            %% Create metric instruments
            Meter = otel_meter_provider:get_meter(erlkoenig_nft, <<"0.8.0">>, undefined),
            _ = otel_meter:create_counter(Meter, 'erlkoenig.nft.counter.packets', #{
                description => <<"Total packets through named counter">>,
                unit => '1'
            }),
            _ = otel_meter:create_counter(Meter, 'erlkoenig.nft.counter.bytes', #{
                description => <<"Total bytes through named counter">>,
                unit => 'By'
            }),
            _ = otel_meter:create_observable_gauge(
                Meter,
                'erlkoenig.nft.counter.pps',
                fun observe_counter_rates/1,
                pps,
                #{description => <<"Packets per second for named counter">>}
            ),
            _ = otel_meter:create_observable_gauge(
                Meter,
                'erlkoenig.nft.counter.bps',
                fun observe_counter_rates/1,
                bps,
                #{description => <<"Bytes per second for named counter">>}
            ),
            _ = otel_meter:create_observable_gauge(
                Meter,
                'erlkoenig.nft.ct.active',
                fun observe_ct_active/1,
                undefined,
                #{description => <<"Active tracked connections">>}
            ),
            _ = otel_meter:create_counter(Meter, 'erlkoenig.nft.ct.new', #{
                description => <<"Total new connections seen">>
            }),
            _ = otel_meter:create_counter(Meter, 'erlkoenig.nft.ct.destroy', #{
                description => <<"Total connections destroyed">>
            }),
            _ = otel_meter:create_observable_gauge(
                Meter,
                'erlkoenig.nft.guard.active_bans',
                fun observe_guard_stats/1,
                active_bans,
                #{description => <<"Currently active IP bans">>}
            ),
            _ = otel_meter:create_counter(Meter, 'erlkoenig.nft.guard.floods', #{
                description => <<"Connection floods detected">>
            }),
            _ = otel_meter:create_counter(Meter, 'erlkoenig.nft.guard.scans', #{
                description => <<"Port scans detected">>
            }),
            _ = otel_meter:create_counter(Meter, 'erlkoenig.nft.guard.bans_issued', #{
                description => <<"Total bans issued">>
            }),
            _ = otel_meter:create_counter(Meter, 'erlkoenig.nft.nflog.packets', #{
                description => <<"Dropped packets logged via NFLOG">>
            }),
            %% Subscribe to all event streams including control_events
            ok = pg:join(erlkoenig_nft, control_events, self()),
            ok = pg:join(erlkoenig_nft, counter_events, self()),
            ok = pg:join(erlkoenig_nft, ct_events, self()),
            ok = pg:join(erlkoenig_nft, nflog_events, self()),
            %% Start guard stats polling
            erlang:send_after(?GUARD_POLL_INTERVAL, self(), poll_guard),
            logger:info("OTel instrumentation active"),
            {ok, #{
                meter => Meter,
                guard_prev => #{},
                ct_new_count => 0,
                ct_destroy_count => 0,
                nflog_count => 0,
                prev_counters => #{}
            }};
        false ->
            ignore
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, not_supported}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

%% --- Control-plane events (post-hoc spans) ---

handle_info(
    {control_event,
        #{kind := op_complete, action := Action, status := Status, details := Details}},
    State
) ->
    SpanName = <<"nft.", (atom_to_binary(Action))/binary>>,
    Attrs = control_event_to_attrs(Action, Status, Details),
    %% Post-hoc span: event representation, NOT a latency measurement.
    %% Span has near-zero duration. This is the correct OTel pattern
    %% for representing completed domain events.
    Tracer = opentelemetry:get_tracer(erlkoenig_nft),
    SpanCtx = otel_tracer:start_span(Tracer, SpanName, #{attributes => Attrs}),
    otel_span:end_span(SpanCtx),
    %% Structured log for security-relevant control events
    maybe_log_control_event(Action, Status, Attrs),
    {noreply, State};
%% --- Counter events (unchanged) ---

handle_info({counter_event, Name, Data}, #{meter := Meter, prev_counters := Prev} = State) ->
    Attrs = #{<<"name">> => Name},
    TotalPkts = maps:get(total_packets, Data, 0),
    TotalBytes = maps:get(total_bytes, Data, 0),
    {PrevPkts, PrevBytes} = maps:get(Name, Prev, {0, 0}),
    DeltaPkts = max(0, TotalPkts - PrevPkts),
    DeltaBytes = max(0, TotalBytes - PrevBytes),
    Ctx = otel_ctx:get_current(),
    otel_counter:add(Ctx, Meter, 'erlkoenig.nft.counter.packets', DeltaPkts, Attrs),
    otel_counter:add(Ctx, Meter, 'erlkoenig.nft.counter.bytes', DeltaBytes, Attrs),
    NewPrev = maps:put(Name, {TotalPkts, TotalBytes}, Prev),
    {noreply, State#{prev_counters := NewPrev}};
%% --- Conntrack events (unchanged) ---

handle_info({ct_new, _Details}, #{meter := Meter, ct_new_count := N} = State) ->
    Ctx = otel_ctx:get_current(),
    otel_counter:add(Ctx, Meter, 'erlkoenig.nft.ct.new', 1, #{}),
    {noreply, State#{ct_new_count := N + 1}};
handle_info({ct_destroy, _Details}, #{meter := Meter, ct_destroy_count := N} = State) ->
    Ctx = otel_ctx:get_current(),
    otel_counter:add(Ctx, Meter, 'erlkoenig.nft.ct.destroy', 1, #{}),
    {noreply, State#{ct_destroy_count := N + 1}};
handle_info({ct_alert, Alert}, State) ->
    emit_log(<<"nft.ct.alert">>, warning, #{
        <<"alert">> => iolist_to_binary(io_lib:format("~p", [Alert]))
    }),
    {noreply, State};
%% --- NFLOG events (unchanged) ---

handle_info({nflog_event, Details}, #{meter := Meter, nflog_count := N} = State) ->
    Ctx = otel_ctx:get_current(),
    otel_counter:add(Ctx, Meter, 'erlkoenig.nft.nflog.packets', 1, #{}),
    Src = maps:get(src, Details, <<>>),
    Dst = maps:get(dst, Details, <<>>),
    Proto = maps:get(proto, Details, <<>>),
    emit_log(<<"nft.nflog.drop">>, warning, #{
        <<"src">> => Src, <<"dst">> => Dst, <<"proto">> => Proto
    }),
    {noreply, State#{nflog_count := N + 1}};
%% --- Guard stats polling (unchanged) ---

handle_info(poll_guard, #{meter := Meter, guard_prev := Prev} = State) ->
    NewPrev =
        try
            Stats = erlkoenig_nft:guard_stats(),
            Ctx = otel_ctx:get_current(),
            Floods = maps:get(floods_detected, Stats, 0),
            Scans = maps:get(scans_detected, Stats, 0),
            BansIssued = maps:get(bans_issued, Stats, 0),
            PrevFloods = maps:get(floods_detected, Prev, 0),
            PrevScans = maps:get(scans_detected, Prev, 0),
            PrevBans = maps:get(bans_issued, Prev, 0),
            case Floods - PrevFloods of
                DF when DF > 0 ->
                    otel_counter:add(Ctx, Meter, 'erlkoenig.nft.guard.floods', DF, #{}),
                    emit_log(<<"nft.guard.flood_detected">>, warning, #{<<"total">> => Floods});
                _ ->
                    ok
            end,
            case Scans - PrevScans of
                DS when DS > 0 ->
                    otel_counter:add(Ctx, Meter, 'erlkoenig.nft.guard.scans', DS, #{}),
                    emit_log(<<"nft.guard.scan_detected">>, warning, #{<<"total">> => Scans});
                _ ->
                    ok
            end,
            case BansIssued - PrevBans of
                DB when DB > 0 ->
                    otel_counter:add(Ctx, Meter, 'erlkoenig.nft.guard.bans_issued', DB, #{});
                _ ->
                    ok
            end,
            Stats
        catch
            _:_ -> Prev
        end,
    erlang:send_after(?GUARD_POLL_INTERVAL, self(), poll_guard),
    {noreply, State#{guard_prev := NewPrev}};
handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%% --- Internal: Control event attribute mapping ---

%% Explicit mapping of known fields. Unknown fields are deliberately ignored
%% to prevent the OTel attribute surface from silently coupling to internal
%% event payload evolution.
-spec control_event_to_attrs(atom(), ok | error, map()) -> map().
control_event_to_attrs(Action, Status, Details) ->
    Base = #{
        <<"nft.action">> => atom_to_binary(Action),
        <<"nft.status">> => atom_to_binary(Status)
    },
    maps:fold(
        fun
            (ip, V, Acc) -> Acc#{<<"nft.ip">> => V};
            (set, V, Acc) -> Acc#{<<"nft.set">> => V};
            (value, V, Acc) -> Acc#{<<"nft.value">> => V};
            (reason, V, Acc) when is_atom(V) -> Acc#{<<"nft.error.reason">> => atom_to_binary(V)};
            (message, V, Acc) when is_binary(V) -> Acc#{<<"nft.error.message">> => V};
            %% Unknown fields: deliberately ignored
            (_, _, Acc) -> Acc
        end,
        Base,
        Details
    ).

%% Log security-relevant control events via Erlang logger with OTel correlation.
-spec maybe_log_control_event(atom(), ok | error, map()) -> ok.
maybe_log_control_event(ban, ok, Attrs) ->
    emit_log(<<"nft.ban">>, warning, Attrs);
maybe_log_control_event(unban, ok, Attrs) ->
    emit_log(<<"nft.unban">>, info, Attrs);
maybe_log_control_event(_, error, Attrs) ->
    emit_log(<<"nft.error">>, warning, Attrs);
maybe_log_control_event(_, _, _) ->
    ok.

%% --- Internal: Observable gauge callbacks ---

observe_counter_rates(Metric) ->
    try
        Rates = erlkoenig_nft:rates(),
        maps:fold(
            fun(Name, RateMap, Acc) ->
                Value = maps:get(Metric, RateMap, 0.0),
                [{Value, #{<<"name">> => Name}} | Acc]
            end,
            [],
            Rates
        )
    catch
        _:_ -> []
    end.

observe_ct_active(_) ->
    try
        [{erlkoenig_nft:ct_count(), #{}}]
    catch
        _:_ -> []
    end.

observe_guard_stats(Key) ->
    try
        Stats = erlkoenig_nft:guard_stats(),
        [{maps:get(Key, Stats, 0), #{}}]
    catch
        _:_ -> []
    end.

%% --- Internal ---

-spec otel_sdk_loaded() -> boolean().
otel_sdk_loaded() ->
    case code:ensure_loaded(otel_batch_processor) of
        {module, otel_batch_processor} -> true;
        _ -> false
    end.

-spec emit_log(binary(), atom(), map()) -> ok.
emit_log(EventName, Severity, Body) ->
    SevText = severity_text(Severity),
    logger:log(Severity, Body#{
        <<"otel.event.name">> => EventName,
        <<"otel.severity">> => SevText
    }),
    ok.

-spec severity_text(atom()) -> binary().
severity_text(debug) -> <<"DEBUG">>;
severity_text(info) -> <<"INFO">>;
severity_text(notice) -> <<"INFO">>;
severity_text(warning) -> <<"WARN">>;
severity_text(error) -> <<"ERROR">>;
severity_text(critical) -> <<"ERROR">>;
severity_text(alert) -> <<"ERROR">>;
severity_text(emergency) -> <<"ERROR">>;
severity_text(_) -> <<"INFO">>.
