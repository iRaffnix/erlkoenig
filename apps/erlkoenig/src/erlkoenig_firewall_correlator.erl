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

-module(erlkoenig_firewall_correlator).
-moduledoc """
Pure firewall event correlation.

This is the simulation core for the future per-source threat actors.
It consumes canonical firewall events and emits higher-level canonical
events such as `scan_suspect`. No processes, no timers, no kernel I/O.
The live actor layer can later use the same rules with real time and
per-IP state.
""".

-export([new/0, new/1, ingest/2, run/1, run/2]).

-type state() :: map().
-type event() :: map().
-type options() :: #{
    scan_window_ms => pos_integer(),
    scan_port_threshold => pos_integer()
}.

-define(DEFAULT_SCAN_WINDOW_MS, 30000).
-define(DEFAULT_SCAN_PORT_THRESHOLD, 4).

-spec new() -> state().
new() ->
    new(#{}).

-spec new(options()) -> state().
new(Options) ->
    #{
        options => #{
            scan_window_ms => maps:get(scan_window_ms, Options, ?DEFAULT_SCAN_WINDOW_MS),
            scan_port_threshold => maps:get(scan_port_threshold, Options, ?DEFAULT_SCAN_PORT_THRESHOLD)
        },
        sources => #{}
    }.

-spec run([term()]) -> [event()].
run(Inputs) ->
    run(Inputs, #{}).

-spec run([term()], options()) -> [event()].
run(Inputs, Options) ->
    {_State, Decisions} =
        lists:foldl(
          fun(Input, {State0, Acc}) ->
              {State1, NewDecisions} = ingest(State0, Input),
              {State1, Acc ++ NewDecisions}
          end,
          {new(Options), []},
          Inputs),
    Decisions.

-spec ingest(state(), term()) -> {state(), [event()]}.
ingest(State, Input) ->
    case erlkoenig_firewall_event:normalize(Input) of
        {ok, #{src_ip := SrcIp, dst_port := Port} = Event} when
            Port =/= undefined, SrcIp =/= undefined
        ->
            correlate_packet(State, Event);
        {ok, _Event} ->
            {State, []};
        skip ->
            {State, []}
    end.

correlate_packet(#{options := Options, sources := Sources0} = State, Event) ->
    SrcIp = maps:get(src_ip, Event),
    Port = maps:get(dst_port, Event),
    Ts = maps:get(ts_wall, Event),
    WindowMs = maps:get(scan_window_ms, Options),
    Threshold = maps:get(scan_port_threshold, Options),
    Source0 = maps:get(SrcIp, Sources0, #{events => [], suspected => false}),
    Events0 = maps:get(events, Source0, []),
    Events1 = prune([{Ts, Port, Event} | Events0], Ts, WindowMs),
    Ports = distinct_ports(Events1),
    Suspected0 = maps:get(suspected, Source0, false),
    Source1 = Source0#{events => Events1},

    case {Suspected0, length(Ports) >= Threshold} of
        {false, true} ->
            Decision = scan_suspect_event(SrcIp, Ports, WindowMs, Events1, Event),
            Source2 = Source1#{suspected => true},
            {State#{sources := Sources0#{SrcIp => Source2}}, [Decision]};
        _ ->
            {State#{sources := Sources0#{SrcIp => Source1}}, []}
    end.

prune(Events, Now, WindowMs) ->
    [Event || {Ts, _Port, _Envelope} = Event <- Events, Now - Ts =< WindowMs].

distinct_ports(Events) ->
    Ports =
        lists:foldl(fun({_Ts, Port, _Event}, Acc) ->
                            case lists:member(Port, Acc) of
                                true -> Acc;
                                false -> [Port | Acc]
                            end
                    end, [], Events),
    lists:sort(Ports).

scan_suspect_event(SrcIp, Ports, WindowMs, Events, Trigger) ->
    Tables = distinct_field(table, Events),
    Chains = distinct_field(chain, Events),
    unwrap(
      erlkoenig_firewall_event:normalize(
        {firewall_event, #{
            source => correlator,
            severity => warning,
            kind => scan_suspect,
            src_ip => SrcIp,
            dst_port => maps:get(dst_port, Trigger),
            reason => scan_distinct_ports,
            evidence => #{
                ports => Ports,
                port_count => length(Ports),
                window_ms => WindowMs,
                sample_count => length(Events),
                tables => Tables,
                chains => Chains
            },
            labels => [firewall, threat, correlation]
        }})).

distinct_field(Field, Events) ->
    Values =
        lists:foldl(fun({_Ts, _Port, Event}, Acc) ->
                            case maps:get(Field, Event, undefined) of
                                undefined -> Acc;
                                Value ->
                                    case lists:member(Value, Acc) of
                                        true -> Acc;
                                        false -> [Value | Acc]
                                    end
                            end
                    end, [], Events),
    lists:sort(Values).

unwrap({ok, Event}) -> Event.
