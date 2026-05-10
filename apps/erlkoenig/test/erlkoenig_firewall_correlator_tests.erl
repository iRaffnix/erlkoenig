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

-module(erlkoenig_firewall_correlator_tests).

-include_lib("eunit/include/eunit.hrl").

distinct_ports_in_window_emit_scan_suspect_test() ->
    Events = [
        packet(0, 22),
        packet(1000, 80),
        packet(2000, 443),
        packet(3000, 5432)
    ],

    [Decision] = erlkoenig_firewall_correlator:run(Events),
    Evidence = maps:get(evidence, Decision),

    ?assertEqual(scan_suspect, maps:get(kind, Decision)),
    ?assertEqual(correlator, maps:get(source, Decision)),
    ?assertEqual(warning, maps:get(severity, Decision)),
    ?assertEqual(<<"203.0.113.44">>, maps:get(src_ip, Decision)),
    ?assertEqual([22, 80, 443, 5432], maps:get(ports, Evidence)),
    ?assertEqual(4, maps:get(port_count, Evidence)),
    ?assertEqual([<<"erlkoenig_host">>], maps:get(tables, Evidence)),
    ?assertEqual([<<"input">>], maps:get(chains, Evidence)).

repeated_same_port_does_not_emit_scan_suspect_test() ->
    Events = [
        packet(0, 22),
        packet(1000, 22),
        packet(2000, 22),
        packet(3000, 22)
    ],

    ?assertEqual([], erlkoenig_firewall_correlator:run(Events)).

ports_outside_window_do_not_emit_scan_suspect_test() ->
    Events = [
        packet(0, 22),
        packet(1000, 80),
        packet(2000, 443),
        packet(40000, 5432)
    ],

    ?assertEqual([], erlkoenig_firewall_correlator:run(Events)).

custom_threshold_can_emit_earlier_test() ->
    Events = [packet(0, 22), packet(1000, 80), packet(2000, 443)],

    [Decision] =
        erlkoenig_firewall_correlator:run(
          Events, #{scan_port_threshold => 3}),

    Evidence = maps:get(evidence, Decision),
    ?assertEqual([22, 80, 443], maps:get(ports, Evidence)).

source_isolation_keeps_independent_actor_state_test() ->
    Events = [
        packet(<<"203.0.113.44">>, 0, 22),
        packet(<<"198.51.100.9">>, 1000, 22),
        packet(<<"203.0.113.44">>, 2000, 80),
        packet(<<"198.51.100.9">>, 3000, 80),
        packet(<<"203.0.113.44">>, 4000, 443),
        packet(<<"203.0.113.44">>, 5000, 5432)
    ],

    [Decision] = erlkoenig_firewall_correlator:run(Events),
    ?assertEqual(<<"203.0.113.44">>, maps:get(src_ip, Decision)).

only_one_suspect_event_per_source_test() ->
    Events = [
        packet(0, 22),
        packet(1000, 80),
        packet(2000, 443),
        packet(3000, 5432),
        packet(4000, 8080)
    ],

    [_Decision] = erlkoenig_firewall_correlator:run(Events).

packet(TsWall, Port) ->
    packet(<<"203.0.113.44">>, TsWall, Port).

packet(SrcIp, TsWall, Port) ->
    {firewall_event, #{
        kind => firewall_packet,
        source => nflog,
        table => <<"erlkoenig_host">>,
        table_owner => host,
        chain => <<"input">>,
        src_ip => SrcIp,
        dst_ip => <<"10.20.30.2">>,
        proto => tcp,
        dst_port => Port,
        verdict => drop,
        ts_wall => TsWall,
        reason => default_drop
    }}.
