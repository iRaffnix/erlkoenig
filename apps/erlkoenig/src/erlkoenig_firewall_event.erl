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

-module(erlkoenig_firewall_event).
-moduledoc """
Canonical firewall event envelope.

This module is deliberately pure: no sockets, no pg, no AMQP, no ETS.
It is the anti-corruption layer between low-level nft/conntrack/threat
messages and operator-facing surfaces such as `ek firewall watch`,
AMQP, dashboards, and future ontology explanations.
""".

-export([normalize/1, amqp/1]).

-type event() :: map().
-type normalize_result() :: {ok, event()} | skip.
-type amqp_result() :: {ok, binary(), map()} | skip.

-spec normalize(term()) -> normalize_result().
normalize({firewall_event, Event}) when is_map(Event) ->
    {ok, ensure_envelope(Event)};
normalize(#{kind := _} = Event) ->
    {ok, ensure_envelope(Event)};
normalize({nflog_event, Event}) when is_map(Event) ->
    {ok, normalize_nflog(Event)};
normalize({counter_event, Name, #{packets := Packets} = Rate}) when Packets > 0 ->
    {ok, normalize_counter(Name, Rate)};
normalize({counter_event, _Name, _Rate}) ->
    skip;
normalize({ct_guard_suspect, #{ip := Ip, ports := Ports} = Details}) ->
    {ok, threat_event(scan_suspect, Ip, Details#{ports => Ports})};
normalize({ct_guard_slow_scan, #{ip := Ip, ports := Ports} = Details}) ->
    {ok, threat_event(slow_scan, Ip, Details#{ports => Ports})};
normalize({ct_guard_honeypot, #{ip := Ip, port := Port} = Details}) ->
    {ok, threat_event(honeypot, Ip, Details#{port => Port})};
normalize({ct_guard_ban, #{ip := Ip, reason := Reason} = Details}) ->
    {ok, threat_event(threat_ban, Ip, Details#{reason => Reason})};
normalize({ct_guard_unban, #{ip := Ip} = Details}) ->
    {ok, threat_event(threat_unban, Ip, Details)};
normalize({ct_guard_ban_failed, #{ip := Ip} = Details}) ->
    {ok, threat_event(threat_ban_failed, Ip, Details)};
normalize({ct_guard_unban_failed, #{ip := Ip} = Details}) ->
    {ok, threat_event(threat_unban_failed, Ip, Details)};
normalize(_Other) ->
    skip.

-doc "Return AMQP routing key and payload for a canonical firewall event.".
-spec amqp(term()) -> amqp_result().
amqp(Input) ->
    case normalize(Input) of
        {ok, Event} ->
            amqp_event(Event);
        skip ->
            skip
    end.

normalize_nflog(Event) ->
    Chain = chain_from_nflog(Event),
    Evidence = maps:without([prefix, src, dst, proto, sport, dport], Event),
    ensure_envelope(#{
        source => nflog,
        severity => notice,
        kind => firewall_packet,
        table => maps:get(table, Event, unknown),
        table_owner => maps:get(table_owner, Event, unknown),
        chain => Chain,
        src_ip => maps:get(src, Event, undefined),
        dst_ip => maps:get(dst, Event, undefined),
        proto => maps:get(proto, Event, unknown),
        src_port => maps:get(sport, Event, undefined),
        dst_port => maps:get(dport, Event, undefined),
        verdict => maps:get(verdict, Event, observe),
        reason => maps:get(reason, Event, packet_observed),
        evidence => Evidence,
        labels => [firewall, packet]
    }).

normalize_counter(Name, Rate) ->
    Counter = ensure_binary(Name),
    Chain = counter_to_chain(Counter),
    ensure_envelope(#{
        source => counter,
        severity => info,
        kind => counter_rate,
        table => maps:get(table, Rate, unknown),
        table_owner => maps:get(table_owner, Rate, unknown),
        chain => Chain,
        counter => Counter,
        reason => counter_rate,
        evidence => #{
            packets => maps:get(packets, Rate, 0),
            bytes => maps:get(bytes, Rate, 0),
            total_packets => maps:get(total_packets, Rate, maps:get(packets, Rate, 0)),
            total_bytes => maps:get(total_bytes, Rate, maps:get(bytes, Rate, 0)),
            pps => maps:get(pps, Rate, 0),
            bps => maps:get(bps, Rate, 0),
            interval => maps:get(interval, Rate, 0)
        },
        labels => [firewall, counter]
    }).

threat_event(Kind, Ip, Details) ->
    Severity =
        case Kind of
            threat_ban -> warning;
            threat_ban_failed -> warning;
            threat_unban_failed -> warning;
            _ -> notice
        end,
    ensure_envelope(#{
        source => threat,
        severity => Severity,
        kind => Kind,
        src_ip => Ip,
        reason => maps:get(reason, Details, Kind),
        evidence => maps:without([ip, reason], Details),
        labels => [firewall, threat]
    }).

ensure_envelope(Event) ->
    Event#{
        id => maps:get(id, Event, event_id()),
        ts_mono => maps:get(ts_mono, Event, erlang:monotonic_time(millisecond)),
        ts_wall => maps:get(ts_wall, Event, erlang:system_time(millisecond)),
        source => maps:get(source, Event, unknown),
        severity => maps:get(severity, Event, info),
        evidence => maps:get(evidence, Event, #{}),
        labels => maps:get(labels, Event, [firewall])
    }.

amqp_event(#{kind := firewall_packet} = Event) ->
    Chain = ensure_binary(maps:get(chain, Event, unknown)),
    {ok, <<"firewall.", Chain/binary, ".packet">>, Event};
amqp_event(#{kind := counter_rate, evidence := #{packets := Packets}} = Event)
  when Packets > 0 ->
    Chain = ensure_binary(maps:get(chain, Event, unknown)),
    {ok, <<"firewall.", Chain/binary, ".drop">>, Event};
amqp_event(#{kind := counter_rate}) ->
    skip;
amqp_event(#{kind := scan_suspect} = Event) ->
    {ok, <<"guard.threat.suspect">>, Event};
amqp_event(#{kind := slow_scan} = Event) ->
    {ok, <<"guard.threat.slow_scan">>, Event};
amqp_event(#{kind := honeypot} = Event) ->
    {ok, <<"guard.threat.honeypot">>, Event};
amqp_event(#{kind := threat_ban} = Event) ->
    {ok, <<"guard.threat.ban">>, Event};
amqp_event(#{kind := threat_unban} = Event) ->
    {ok, <<"guard.threat.unban">>, Event};
amqp_event(#{kind := threat_ban_failed} = Event) ->
    {ok, <<"guard.threat.ban_failed">>, Event};
amqp_event(#{kind := threat_unban_failed} = Event) ->
    {ok, <<"guard.threat.unban_failed">>, Event};
amqp_event(#{kind := Kind} = Event) ->
    KindBin = ensure_binary(Kind),
    {ok, <<"firewall.unknown.", KindBin/binary>>, Event}.

chain_from_nflog(#{chain := Chain}) ->
    ensure_binary(Chain);
chain_from_nflog(#{prefix := Prefix}) ->
    PrefixBin = ensure_binary(Prefix),
    case binary:split(PrefixBin, <<"_drop">>) of
        [Chain, _] -> Chain;
        _ -> PrefixBin
    end;
chain_from_nflog(_) ->
    <<"unknown">>.

counter_to_chain(Name) ->
    NameBin = ensure_binary(Name),
    case binary:split(NameBin, <<"_drop">>) of
        [Chain, _] -> Chain;
        _ -> NameBin
    end.

event_id() ->
    Unique = erlang:unique_integer([monotonic, positive]),
    iolist_to_binary(io_lib:format("fw-~B-~B", [erlang:system_time(millisecond), Unique])).

ensure_binary(B) when is_binary(B) ->
    B;
ensure_binary(A) when is_atom(A) ->
    atom_to_binary(A);
ensure_binary(I) when is_integer(I) ->
    integer_to_binary(I);
ensure_binary(L) when is_list(L) ->
    unicode:characters_to_binary(L);
ensure_binary(T) ->
    iolist_to_binary(io_lib:format("~p", [T])).
