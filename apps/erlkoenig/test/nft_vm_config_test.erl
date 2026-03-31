-module(nft_vm_config_test).
-include_lib("eunit/include/eunit.hrl").

%% --- Load tests ---

load_webserver_test() ->
    {ok, ChainMap} = nft_vm_config:load("etc/firewall.term"),
    ?assert(is_map(ChainMap)),
    ?assert(maps:is_key(<<"inbound">>, ChainMap)),
    ?assert(maps:is_key(<<"prerouting_ban">>, ChainMap)),
    %% inbound: ct_established + iifname_accept + tcp_accept_limited(2) +
    %%          tcp_accept(80) + tcp_accept(443) + icmp + protocol_accept + log_drop = 9
    ?assertEqual(9, length(maps:get(<<"inbound">>, ChainMap))),
    %% prerouting_ban: 2 set_lookup_drop
    ?assertEqual(2, length(maps:get(<<"prerouting_ban">>, ChainMap))).

load_anti_spoofing_test() ->
    {ok, ChainMap} = nft_vm_config:load("examples/anti_spoofing.term"),
    ?assert(maps:is_key(<<"inbound">>, ChainMap)),
    ?assert(maps:is_key(<<"ssh_chain">>, ChainMap)),
    ?assert(maps:is_key(<<"http_chain">>, ChainMap)),
    ?assert(maps:is_key(<<"forward">>, ChainMap)),
    ?assert(maps:is_key(<<"raw_prerouting">>, ChainMap)).

load_term_test() ->
    {ok, [Config]} = file:consult("etc/firewall.term"),
    ChainMap = nft_vm_config:load_term(Config),
    ?assert(maps:is_key(<<"inbound">>, ChainMap)),
    ?assertEqual(9, length(maps:get(<<"inbound">>, ChainMap))).

load_chain_test() ->
    {ok, Rules} = nft_vm_config:load_chain("etc/firewall.term", <<"inbound">>),
    ?assertEqual(9, length(Rules)).

load_chain_unknown_test() ->
    {error, {unknown_chain, <<"nope">>, _}} =
        nft_vm_config:load_chain("etc/firewall.term", <<"nope">>).

%% --- Error tests ---

load_missing_file_test() ->
    {error, {file_error, "/nonexistent.term", enoent}} =
        nft_vm_config:load("/nonexistent.term").

load_bad_format_test() ->
    ok = file:write_file("/tmp/nft_vm_config_bad.term", <<"not_a_map.">>),
    {error, {bad_config_format, not_a_map}} =
        nft_vm_config:load("/tmp/nft_vm_config_bad.term").

load_syntax_error_test() ->
    ok = file:write_file("/tmp/nft_vm_config_broken.term", <<"#{foo => }">>),
    {error, {file_error, _, _}} =
        nft_vm_config:load("/tmp/nft_vm_config_broken.term").

load_empty_config_test() ->
    ok = file:write_file("/tmp/nft_vm_config_empty.term", <<"">>),
    {error, empty_config} =
        nft_vm_config:load("/tmp/nft_vm_config_empty.term").

%% --- Rule structure tests ---

rules_are_expression_lists_test() ->
    {ok, ChainMap} = nft_vm_config:load("etc/firewall.term"),
    Rules = maps:get(<<"inbound">>, ChainMap),
    %% Each rule is a list of {Type, Opts} tuples
    lists:foreach(fun(Rule) ->
        ?assert(is_list(Rule)),
        ?assert(length(Rule) > 0),
        lists:foreach(fun(Expr) ->
            ?assertMatch({_, _}, Expr),
            {Type, Opts} = Expr,
            ?assert(is_atom(Type)),
            ?assert(is_map(Opts))
        end, Rule)
    end, Rules).

multi_rule_expansion_test() ->
    %% tcp_accept_limited returns 2 rules. Verify they are separate.
    Config = #{
        chains => [
            #{name => <<"test">>,
              rules => [{tcp_accept_limited, 22, <<"ssh">>, #{burst => 5, rate => 25}}]}
        ]
    },
    ChainMap = nft_vm_config:load_term(Config),
    Rules = maps:get(<<"test">>, ChainMap),
    ?assertEqual(2, length(Rules)),
    %% Each rule should be a list of expressions, not mixed
    [R1, R2] = Rules,
    ?assert(length(R1) > 0),
    ?assert(length(R2) > 0).

%% --- VM evaluation integration tests ---

eval_ssh_accept_test() ->
    {ok, ChainMap} = nft_vm_config:load("etc/firewall.term"),
    Rules = maps:get(<<"inbound">>, ChainMap),
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 22}),
    {Verdict, _Trace} = nft_vm:eval_chain(Rules, Pkt, drop),
    ?assertEqual(accept, Verdict).

eval_http_accept_test() ->
    {ok, ChainMap} = nft_vm_config:load("etc/firewall.term"),
    Rules = maps:get(<<"inbound">>, ChainMap),
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80}),
    {Verdict, _} = nft_vm:eval_chain(Rules, Pkt, drop),
    ?assertEqual(accept, Verdict).

eval_random_udp_drop_test() ->
    {ok, ChainMap} = nft_vm_config:load("etc/firewall.term"),
    Rules = maps:get(<<"inbound">>, ChainMap),
    Pkt = nft_vm_pkt:udp(#{saddr => {10,0,0,1}}, #{dport => 12345}),
    {Verdict, _} = nft_vm:eval_chain(Rules, Pkt, drop),
    ?assertEqual(drop, Verdict).

eval_icmp_accept_test() ->
    {ok, ChainMap} = nft_vm_config:load("etc/firewall.term"),
    Rules = maps:get(<<"inbound">>, ChainMap),
    Pkt = nft_vm_pkt:icmp(#{saddr => {10,0,0,1}}, #{type => echo_request}),
    {Verdict, _} = nft_vm:eval_chain(Rules, Pkt, drop),
    ?assertEqual(accept, Verdict).

eval_established_accept_test() ->
    {ok, ChainMap} = nft_vm_config:load("etc/firewall.term"),
    Rules = maps:get(<<"inbound">>, ChainMap),
    %% ct_state goes in Meta (3rd arg), not IpOpts
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 9999}, #{ct_state => established}),
    {Verdict, _} = nft_vm:eval_chain(Rules, Pkt, drop),
    ?assertEqual(accept, Verdict).

eval_set_lookup_test() ->
    {ok, ChainMap} = nft_vm_config:load("etc/firewall.term"),
    Rules = maps:get(<<"prerouting_ban">>, ChainMap),
    %% Banned IP should be dropped (set elements as 4-byte binaries)
    Pkt1 = nft_vm_pkt:tcp(#{saddr => {192,0,2,99}}, #{dport => 80}),
    PktBanned = nft_vm_pkt:with_sets(Pkt1, #{<<"blocklist">> => [<<192,0,2,99>>]}),
    {V1, _} = nft_vm:eval_chain(Rules, PktBanned, accept),
    ?assertEqual(drop, V1),
    %% Clean IP should pass (default policy accept)
    Pkt2 = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}}, #{dport => 80}),
    PktClean = nft_vm_pkt:with_sets(Pkt2, #{<<"blocklist">> => [<<192,0,2,99>>]}),
    {V2, _} = nft_vm:eval_chain(Rules, PktClean, accept),
    ?assertEqual(accept, V2).

eval_vmap_dispatch_test() ->
    {ok, [Config]} = file:consult("examples/anti_spoofing.term"),
    ChainMap = nft_vm_config:load_term(Config),
    VmapMap = nft_vm_config:vmap_map(Config),
    Rules = maps:get(<<"inbound">>, ChainMap),
    Pkt = nft_vm_pkt:tcp(#{saddr => {10,0,0,1}, ct_state => new, iifname => <<"eth0">>}, #{dport => 22}),
    PktV = nft_vm_pkt:with_vmaps(Pkt, VmapMap),
    {Verdict, _} = nft_vm:eval_chain(Rules, PktV, drop),
    ?assertEqual({jump, <<"ssh_chain">>}, Verdict).

%% --- Vmap extraction ---

vmap_map_test() ->
    {ok, [Config]} = file:consult("examples/anti_spoofing.term"),
    VmapMap = nft_vm_config:vmap_map(Config),
    ?assert(maps:is_key(<<"port_vmap">>, VmapMap)),
    Entries = maps:get(<<"port_vmap">>, VmapMap),
    ?assert(maps:size(Entries) >= 3).

vmap_map_empty_test() ->
    ?assertEqual(#{}, nft_vm_config:vmap_map(#{})).

%% --- Unknown rule type ---

unknown_rule_type_test() ->
    Config = #{chains => [#{name => <<"test">>, rules => [{totally_unknown_rule, 42}]}]},
    ?assertError({unknown_rule_type, {totally_unknown_rule, 42}},
                 nft_vm_config:load_term(Config)).
