-module(nft_vm_scenario_test).
-include_lib("eunit/include/eunit.hrl").

%% --- Scenario loading ---

run_file_test() ->
    {ok, Result} = nft_vm_scenario:run_file("examples/webserver.scenario.term"),
    ?assertEqual(6, maps:get(total, Result)),
    ?assertEqual(6, maps:get(passed, Result)),
    ?assertEqual(0, maps:get(failed, Result)).

run_file_with_fail_test() ->
    {ok, Result} = nft_vm_scenario:run_file("examples/webserver_fail.scenario.term"),
    ?assertEqual(2, maps:get(total, Result)),
    ?assertEqual(1, maps:get(passed, Result)),
    ?assertEqual(1, maps:get(failed, Result)).

run_term_test() ->
    Scenario = #{
        config => "etc/firewall.term",
        chain => <<"inbound">>,
        policy => drop,
        packets => [
            #{name => <<"ssh">>, proto => tcp, saddr => {10,0,0,1}, dport => 22, expect => accept},
            #{name => <<"drop">>, proto => udp, saddr => {10,0,0,1}, dport => 9999, expect => drop}
        ]
    },
    {ok, Result} = nft_vm_scenario:run(Scenario),
    ?assertEqual(2, maps:get(passed, Result)),
    ?assertEqual(0, maps:get(failed, Result)).

%% --- Error handling ---

run_file_missing_test() ->
    {error, {file_error, "/nonexistent.scenario.term", enoent}} =
        nft_vm_scenario:run_file("/nonexistent.scenario.term").

run_file_bad_format_test() ->
    ok = file:write_file("/tmp/bad.scenario.term", <<"not_a_map.">>),
    {error, {bad_scenario_format, not_a_map}} =
        nft_vm_scenario:run_file("/tmp/bad.scenario.term").

run_bad_config_test() ->
    Scenario = #{
        config => "/nonexistent/firewall.term",
        chain => <<"input">>,
        packets => [#{name => <<"x">>, proto => tcp, saddr => {10,0,0,1}, dport => 22, expect => accept}]
    },
    {error, {file_error, _, enoent}} = nft_vm_scenario:run(Scenario).

run_unknown_chain_test() ->
    Scenario = #{
        config => "etc/firewall.term",
        chain => <<"nonexistent">>,
        packets => [#{name => <<"x">>, proto => tcp, saddr => {10,0,0,1}, dport => 22, expect => accept}]
    },
    {error, {unknown_chain, <<"nonexistent">>, _}} = nft_vm_scenario:run(Scenario).

%% --- Packet types ---

tcp_packet_test() ->
    Scenario = #{
        config => "etc/firewall.term",
        chain => <<"inbound">>,
        policy => drop,
        packets => [
            #{name => <<"tcp">>, proto => tcp, saddr => {10,0,0,1}, dport => 80, expect => accept}
        ]
    },
    {ok, Result} = nft_vm_scenario:run(Scenario),
    ?assertEqual(1, maps:get(passed, Result)).

udp_packet_test() ->
    Scenario = #{
        config => "etc/firewall.term",
        chain => <<"inbound">>,
        policy => drop,
        packets => [
            #{name => <<"udp">>, proto => udp, saddr => {10,0,0,1}, dport => 12345, expect => drop}
        ]
    },
    {ok, Result} = nft_vm_scenario:run(Scenario),
    ?assertEqual(1, maps:get(passed, Result)).

icmp_packet_test() ->
    Scenario = #{
        config => "etc/firewall.term",
        chain => <<"inbound">>,
        policy => drop,
        packets => [
            #{name => <<"icmp">>, proto => icmp, saddr => {10,0,0,1}, expect => accept}
        ]
    },
    {ok, Result} = nft_vm_scenario:run(Scenario),
    ?assertEqual(1, maps:get(passed, Result)).

%% --- Set injection ---

set_injection_test() ->
    Scenario = #{
        config => "etc/firewall.term",
        chain => <<"prerouting_ban">>,
        policy => accept,
        sets => #{<<"blocklist">> => [{192,0,2,99}]},
        packets => [
            #{name => <<"banned">>, proto => tcp, saddr => {192,0,2,99}, dport => 80, expect => drop},
            #{name => <<"clean">>, proto => tcp, saddr => {10,0,0,1}, dport => 80, expect => accept}
        ]
    },
    {ok, Result} = nft_vm_scenario:run(Scenario),
    ?assertEqual(2, maps:get(passed, Result)).

%% --- ct_state via meta ---

ct_state_test() ->
    Scenario = #{
        config => "etc/firewall.term",
        chain => <<"inbound">>,
        policy => drop,
        packets => [
            #{name => <<"established">>, proto => tcp, saddr => {10,0,0,1},
              dport => 9999, ct_state => established, expect => accept}
        ]
    },
    {ok, Result} = nft_vm_scenario:run(Scenario),
    ?assertEqual(1, maps:get(passed, Result)).

%% --- Result structure ---

result_structure_test() ->
    {ok, Result} = nft_vm_scenario:run_file("examples/webserver.scenario.term"),
    ?assert(is_binary(maps:get(chain, Result))),
    ?assert(is_atom(maps:get(policy, Result))),
    Results = maps:get(results, Result),
    lists:foreach(fun(R) ->
        ?assert(is_binary(maps:get(name, R))),
        ?assert(is_atom(maps:get(expected, R))),
        ?assert(is_atom(maps:get(actual, R))),
        ?assert(is_boolean(maps:get(pass, R))),
        ?assert(is_list(maps:get(trace, R)))
    end, Results).

%% --- Rule index ---

rule_index_test() ->
    {ok, Result} = nft_vm_scenario:run_file("examples/webserver.scenario.term"),
    Results = maps:get(results, Result),
    %% established -> rule 1 (ct_established_accept)
    EstResult = lists:keyfind(<<"established">>, 1,
        [{maps:get(name, R), R} || R <- Results]),
    {<<"established">>, Est} = EstResult,
    ?assertEqual(1, maps:get(rule_index, Est)).

%% --- Formatting ---

format_results_test() ->
    {ok, Result} = nft_vm_scenario:run_file("examples/webserver.scenario.term"),
    Output = iolist_to_binary(nft_vm_scenario:format_results(Result)),
    ?assertNotEqual(nomatch, binary:match(Output, <<"6 packets">>)),
    ?assertNotEqual(nomatch, binary:match(Output, <<"6 passed">>)),
    ?assertNotEqual(nomatch, binary:match(Output, <<"0 failed">>)).

format_failure_shows_trace_test() ->
    {ok, Result} = nft_vm_scenario:run_file("examples/webserver_fail.scenario.term"),
    Output = iolist_to_binary(nft_vm_scenario:format_results(Result)),
    ?assertNotEqual(nomatch, binary:match(Output, <<"FAIL">>)),
    ?assertNotEqual(nomatch, binary:match(Output, <<"Trace:">>)).
