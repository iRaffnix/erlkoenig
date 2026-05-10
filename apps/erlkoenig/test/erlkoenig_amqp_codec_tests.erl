%%%-------------------------------------------------------------------
%%% @doc Unit tests for the new audit + capability AMQP codec branches.
%%%
%%% The wider codec covers many event types; we focus here on the
%%% three additions tied to the SPEC-AS-005 audit chain and the
%%% capability framework, since they're the most recently-added and
%%% most likely to drift from the dashboard contract.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_amqp_codec_tests).

-include_lib("eunit/include/eunit.hrl").

%% Note: routing_key/1 and encode_payload/1 are exported only
%% under -ifdef(TEST), which the rebar3 EUnit profile defines.

audit_sealed_test() ->
    Info = #{sealed_path => <<"/var/log/erlkoenig/audit.jsonl.2026-04-19.sealed">>,
             event_count => 12345,
             byte_count  => 4321098,
             anchor      => <<"e2c9deadbeefcafe">>},
    {ok, Key, Payload} =
        erlkoenig_amqp_codec:encode_payload({audit_sealed, Info}),
    ?assertEqual(<<"audit.chain.sealed">>, Key),
    ?assertEqual(<<"/var/log/erlkoenig/audit.jsonl.2026-04-19.sealed">>,
                 maps:get(<<"sealed_path">>, Payload)),
    ?assertEqual(12345,   maps:get(<<"event_count">>, Payload)),
    ?assertEqual(4321098, maps:get(<<"byte_count">>, Payload)),
    ?assertEqual(<<"e2c9deadbeefcafe">>,
                 maps:get(<<"anchor">>, Payload)).

audit_chain_break_test() ->
    Detail = #{path => <<"/var/log/erlkoenig/audit.jsonl">>,
               line => 42,
               reason => {chain_break, this_hash_mismatch}},
    {ok, Key, Payload} =
        erlkoenig_amqp_codec:encode_payload({audit_chain_break, Detail}),
    ?assertEqual(<<"audit.chain.broken">>, Key),
    ?assertEqual(<<"/var/log/erlkoenig/audit.jsonl">>,
                 maps:get(<<"path">>, Payload)),
    ?assertEqual(42, maps:get(<<"line">>, Payload)),
    %% reason is rendered via ~p; check substring match.
    ReasonBin = maps:get(<<"reason">>, Payload),
    ?assert(is_binary(ReasonBin)),
    ?assertNotEqual(nomatch,
                    binary:match(ReasonBin, <<"this_hash_mismatch">>)).

capability_unmet_dns_test() ->
    {ok, Key, Payload} =
        erlkoenig_amqp_codec:encode_payload(
          {capability_unmet, <<"abc-123">>, <<"web-0">>,
           'dns.local', no_resolv_conf}),
    %% Routing key carries the capability name so dashboards can
    %% bind on `capability.unmet.dns.local` specifically.
    ?assertEqual(<<"capability.unmet.dns.local">>, Key),
    ?assertEqual(<<"abc-123">>, maps:get(<<"id">>, Payload)),
    ?assertEqual(<<"web-0">>,   maps:get(<<"name">>, Payload)),
    ?assertEqual(<<"dns.local">>, maps:get(<<"capability">>, Payload)),
    ?assertEqual(<<"no_resolv_conf">>, maps:get(<<"action">>, Payload)).

ct_guard_unban_failed_test() ->
    {ok, Key, Payload} =
        erlkoenig_amqp_codec:encode_payload(
          {ct_guard_unban_failed,
           #{ip => <<10, 0, 0, 7>>,
             code => 'EK_THREAT_KERNEL_UNBAN_REJECTED'}}),
    ?assertEqual(<<"guard.threat.unban_failed">>, Key),
    ?assertEqual(<<"10.0.0.7">>, maps:get(<<"ip">>, Payload)),
    ?assertEqual(<<"EK_THREAT_KERNEL_UNBAN_REJECTED">>,
                 maps:get(<<"code">>, Payload)).

canonical_firewall_event_routes_to_packet_family_test() ->
    {ok, Key, Payload} =
        erlkoenig_amqp_codec:encode_payload(
          {firewall_event, #{kind => firewall_packet,
                             source => nflog,
                             chain => <<"input">>,
                             src_ip => {203, 0, 113, 44},
                             dst_port => 22,
                             evidence => #{len => 60,
                                           src_raw => <<203, 0, 113, 44>>,
                                           dst_raw => <<10, 0, 0, 1>>}}}),

    ?assertEqual(<<"firewall.input.packet">>, Key),
    ?assertEqual(<<"firewall_packet">>, maps:get(<<"kind">>, Payload)),
    ?assertEqual(<<"nflog">>, maps:get(<<"source">>, Payload)),
    ?assertEqual(<<"203.0.113.44">>, maps:get(<<"src_ip">>, Payload)),
    ?assertEqual(22, maps:get(<<"dst_port">>, Payload)),
    Evidence = maps:get(<<"evidence">>, Payload),
    ?assertEqual(60, maps:get(<<"len">>, Evidence)),
    ?assertEqual(<<"203.0.113.44">>, maps:get(<<"src_raw">>, Evidence)),
    ?assertEqual(<<"10.0.0.1">>, maps:get(<<"dst_raw">>, Evidence)).

canonical_firewall_event_routes_to_guard_family_test() ->
    {ok, Key, Payload} =
        erlkoenig_amqp_codec:encode_payload(
          {firewall_event, #{kind => scan_suspect,
                             source => threat,
                             src_ip => <<"203.0.113.44">>,
                             evidence => #{ports => [22, 80]}}}),

    ?assertEqual(<<"guard.threat.suspect">>, Key),
    ?assertEqual(<<"scan_suspect">>, maps:get(<<"kind">>, Payload)),
    ?assertEqual(<<"threat">>, maps:get(<<"source">>, Payload)).

%% Sanity: the full encode/1 path (envelope + JSON) wraps these
%% correctly. We just check it produces an iolist that decodes back
%% to a map containing our routing key — anything else means the
%% envelope wrapper got broken.
encode_envelope_roundtrip_test() ->
    Info = #{sealed_path => <<"/tmp/x.sealed">>,
             event_count => 1, byte_count => 100,
             anchor      => <<"deadbeef">>},
    {ok, _RoutingKey, JsonIo} =
        erlkoenig_amqp_codec:encode({audit_sealed, Info}),
    Decoded = json:decode(iolist_to_binary(JsonIo)),
    ?assertEqual(<<"audit.chain.sealed">>, maps:get(<<"key">>, Decoded)),
    ?assertEqual(2, maps:get(<<"v">>, Decoded)),
    ?assert(is_binary(maps:get(<<"ts">>, Decoded))),
    Payload = maps:get(<<"payload">>, Decoded),
    ?assertEqual(<<"deadbeef">>, maps:get(<<"anchor">>, Payload)).
