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

-module(erlkoenig_firewall_event_tests).

-include_lib("eunit/include/eunit.hrl").

nflog_event_normalizes_to_packet_envelope_test() ->
    Raw = {nflog_event, #{
        prefix => <<"input_drop">>,
        src => <<"203.0.113.44">>,
        dst => <<"10.20.30.2">>,
        proto => <<"tcp">>,
        sport => 54321,
        dport => 22,
        table => <<"erlkoenig_host">>,
        table_owner => host,
        len => 60
    }},

    ?assertMatch({ok, #{}}, erlkoenig_firewall_event:normalize(Raw)),
    {ok, Event} = erlkoenig_firewall_event:normalize(Raw),

    ?assertEqual(firewall_packet, maps:get(kind, Event)),
    ?assertEqual(nflog, maps:get(source, Event)),
    ?assertEqual(<<"input">>, maps:get(chain, Event)),
    ?assertEqual(<<"erlkoenig_host">>, maps:get(table, Event)),
    ?assertEqual(host, maps:get(table_owner, Event)),
    ?assertEqual(<<"203.0.113.44">>, maps:get(src_ip, Event)),
    ?assertEqual(22, maps:get(dst_port, Event)),
    ?assert(maps:is_key(id, Event)),
    ?assert(maps:is_key(ts_wall, Event)).

counter_event_normalizes_to_counter_rate_test() ->
    Raw = {counter_event, <<"forward_drop">>, #{
        table => <<"erlkoenig_zone">>,
        table_owner => zone,
        packets => 12,
        bytes => 960,
        pps => 6.0,
        bps => 480.0,
        interval => 2000
    }},

    {ok, Event} = erlkoenig_firewall_event:normalize(Raw),
    Evidence = maps:get(evidence, Event),

    ?assertEqual(counter_rate, maps:get(kind, Event)),
    ?assertEqual(counter, maps:get(source, Event)),
    ?assertEqual(<<"erlkoenig_zone">>, maps:get(table, Event)),
    ?assertEqual(zone, maps:get(table_owner, Event)),
    ?assertEqual(<<"forward">>, maps:get(chain, Event)),
    ?assertEqual(<<"forward_drop">>, maps:get(counter, Event)),
    ?assertEqual(12, maps:get(packets, Evidence)),
    ?assertEqual(6.0, maps:get(pps, Evidence)).

zero_packet_counter_is_skipped_test() ->
    ?assertEqual(skip,
                 erlkoenig_firewall_event:normalize(
                   {counter_event, <<"input_drop">>, #{packets => 0}})).

guard_suspect_normalizes_to_threat_event_test() ->
    Raw = {ct_guard_suspect, #{ip => {203, 0, 113, 44}, ports => [22, 80, 443]}},

    {ok, Event} = erlkoenig_firewall_event:normalize(Raw),
    Evidence = maps:get(evidence, Event),

    ?assertEqual(scan_suspect, maps:get(kind, Event)),
    ?assertEqual(threat, maps:get(source, Event)),
    ?assertEqual({203, 0, 113, 44}, maps:get(src_ip, Event)),
    ?assertEqual([22, 80, 443], maps:get(ports, Evidence)).

amqp_routes_packet_events_to_firewall_chain_packet_test() ->
    {ok, RoutingKey, Payload} =
        erlkoenig_firewall_event:amqp(
          {firewall_event, #{kind => firewall_packet,
                             source => nflog,
                             chain => <<"input">>}}),

    ?assertEqual(<<"firewall.input.packet">>, RoutingKey),
    ?assertEqual(firewall_packet, maps:get(kind, Payload)).

amqp_routes_drop_counters_to_drop_test() ->
    {ok, RoutingKey, Payload} =
        erlkoenig_firewall_event:amqp(
          {counter_event, <<"input_drop">>,
           #{packets => 3, bytes => 180}}),

    ?assertEqual(<<"firewall.input.drop">>, RoutingKey),
    ?assertEqual(<<"input_drop">>, maps:get(counter, Payload)).

amqp_routes_non_drop_counters_to_counter_test() ->
    {ok, RoutingKey, Payload} =
        erlkoenig_firewall_event:amqp(
          {counter_event, <<"live_ssh_accept">>,
           #{packets => 1, bytes => 60}}),

    ?assertEqual(<<"firewall.live_ssh_accept.counter">>, RoutingKey),
    ?assertEqual(<<"live_ssh_accept">>, maps:get(counter, Payload)).

amqp_routes_suspect_events_to_guard_family_test() ->
    {ok, RoutingKey, Payload} =
        erlkoenig_firewall_event:amqp(
          {ct_guard_suspect, #{ip => <<"203.0.113.44">>, ports => [22, 80]}}),

    ?assertEqual(<<"guard.threat.suspect">>, RoutingKey),
    ?assertEqual(scan_suspect, maps:get(kind, Payload)).
