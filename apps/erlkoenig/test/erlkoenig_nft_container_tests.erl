%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_nft_container.
%%%
%%% Two surfaces are exercised:
%%%
%%%  1. translate_opts/1 — the validation seam that maps DSL keys to
%%%     internal keys for compile_generic_rule. Must fail loud on
%%%     typos and on cross-container refs (replica_ips/veth_of) that
%%%     cannot be resolved in a container-local netns.
%%%
%%%  2. build_batch/{1,2} — end-to-end binary emission. We only assert
%%%     the blob is non-empty, that table name is honoured, and that
%%%     empty-rule / multi-chain shapes don't crash.
%%%
%%% SPEC-EK-023 §3 is the source of truth for allowed rule options.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_nft_container_tests).

-include("nft_constants.hrl").
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% translate_opts — per-key mapping
%%%===================================================================

translate_opts_test_() ->
    [{"empty map passes through", fun t_empty_map/0},
     {"ct_state takes head of list", fun t_ct_state_head/0},
     {"tcp_dport maps to tcp", fun t_tcp_dport/0},
     {"udp_dport maps to udp", fun t_udp_dport/0},
     {"iifname normalised to binary", fun t_iifname_binary/0},
     {"oifname normalised to binary", fun t_oifname_binary/0},
     {"oifname_ne maps to oif_neq", fun t_oifname_ne/0},
     {"ip_saddr 4-tuple gets /32 prefix", fun t_saddr_4tuple/0},
     {"ip_saddr 5-tuple keeps prefix", fun t_saddr_5tuple/0},
     {"ip_daddr 4-tuple gets /32 prefix", fun t_daddr_4tuple/0},
     {"ip_daddr 5-tuple keeps prefix", fun t_daddr_5tuple/0},
     {"ip_protocol maps to protocol", fun t_ip_protocol/0},
     {"log_prefix maps to log", fun t_log_prefix/0},
     {"counter normalised to binary", fun t_counter_binary/0},
     {"max and over pass through", fun t_max_over/0}].

t_empty_map() ->
    ?assertEqual(#{}, erlkoenig_nft_container:translate_opts(#{})).

t_ct_state_head() ->
    %% ct_state in DSL is a list (multiple states). Internal rule builder
    %% expects a single atom. Module explicitly takes hd/1 — if that changes
    %% to e.g. lists:last/1, this catches the drift.
    ?assertMatch(#{ct := established},
                 erlkoenig_nft_container:translate_opts(
                     #{ct_state => [established, related]})).

t_tcp_dport() ->
    ?assertMatch(#{tcp := 5432},
                 erlkoenig_nft_container:translate_opts(#{tcp_dport => 5432})).

t_udp_dport() ->
    ?assertMatch(#{udp := 53},
                 erlkoenig_nft_container:translate_opts(#{udp_dport => 53})).

t_iifname_binary() ->
    %% Accepts iolist (charlist), emits binary.
    #{iif := Iif1} = erlkoenig_nft_container:translate_opts(
                        #{iifname => "eth0"}),
    ?assertEqual(<<"eth0">>, Iif1),
    #{iif := Iif2} = erlkoenig_nft_container:translate_opts(
                        #{iifname => <<"eth0">>}),
    ?assertEqual(<<"eth0">>, Iif2).

t_oifname_binary() ->
    ?assertMatch(#{oif := <<"eth0">>},
                 erlkoenig_nft_container:translate_opts(
                     #{oifname => "eth0"})).

t_oifname_ne() ->
    ?assertMatch(#{oif_neq := <<"lo">>},
                 erlkoenig_nft_container:translate_opts(
                     #{oifname_ne => <<"lo">>})).

t_saddr_4tuple() ->
    %% The 4-tuple form is shorthand for a /32 host route.
    ?assertMatch(#{saddr := {10, 0, 0, 1, 32}},
                 erlkoenig_nft_container:translate_opts(
                     #{ip_saddr => {10, 0, 0, 1}})).

t_saddr_5tuple() ->
    ?assertMatch(#{saddr := {10, 0, 0, 0, 24}},
                 erlkoenig_nft_container:translate_opts(
                     #{ip_saddr => {10, 0, 0, 0, 24}})).

t_daddr_4tuple() ->
    ?assertMatch(#{daddr := {192, 168, 1, 5, 32}},
                 erlkoenig_nft_container:translate_opts(
                     #{ip_daddr => {192, 168, 1, 5}})).

t_daddr_5tuple() ->
    ?assertMatch(#{daddr := {192, 168, 1, 0, 24}},
                 erlkoenig_nft_container:translate_opts(
                     #{ip_daddr => {192, 168, 1, 0, 24}})).

t_ip_protocol() ->
    ?assertMatch(#{protocol := tcp},
                 erlkoenig_nft_container:translate_opts(#{ip_protocol => tcp})).

t_log_prefix() ->
    ?assertMatch(#{log := <<"drop:">>},
                 erlkoenig_nft_container:translate_opts(
                     #{log_prefix => <<"drop:">>})).

t_counter_binary() ->
    %% Accepts iolist too.
    ?assertMatch(#{counter := <<"inbound">>},
                 erlkoenig_nft_container:translate_opts(
                     #{counter => "inbound"})).

t_max_over() ->
    %% conn_limit sugar — these are integers only.
    ?assertMatch(#{max := 100, over := 50},
                 erlkoenig_nft_container:translate_opts(
                     #{max => 100, over => 50})).

%%%===================================================================
%%% translate_opts — error surface (Glasbox: fail loud on unresolvable)
%%%===================================================================

translate_opts_errors_test_() ->
    [{"unknown key is rejected with typo hint",
      fun t_unknown_key_errors/0},
     {"replica_ips on ip_saddr raises unresolvable",
      fun t_replica_ips_saddr_errors/0},
     {"replica_ips on ip_daddr raises unresolvable",
      fun t_replica_ips_daddr_errors/0},
     {"veth_of on iifname raises unresolvable",
      fun t_veth_of_iifname_errors/0},
     {"veth_of on oifname raises unresolvable",
      fun t_veth_of_oifname_errors/0},
     {"veth_of on oifname_ne raises unresolvable",
      fun t_veth_of_oifname_ne_errors/0}].

t_unknown_key_errors() ->
    %% Typo like ip_saddrr must raise, not silently drop.
    ?assertError({unknown_container_nft_rule_opt, #{key := ip_saddrr}},
                 erlkoenig_nft_container:translate_opts(
                     #{ip_saddrr => {10, 0, 0, 1}})).

t_replica_ips_saddr_errors() ->
    ?assertError({unresolvable_replica_ips_in_container_nft,
                  #{key := ip_saddr, pod := <<"backend">>,
                    container := <<"api">>}},
                 erlkoenig_nft_container:translate_opts(
                     #{ip_saddr => {replica_ips, <<"backend">>, <<"api">>}})).

t_replica_ips_daddr_errors() ->
    ?assertError({unresolvable_replica_ips_in_container_nft,
                  #{key := ip_daddr}},
                 erlkoenig_nft_container:translate_opts(
                     #{ip_daddr => {replica_ips, <<"backend">>, <<"api">>}})).

t_veth_of_iifname_errors() ->
    ?assertError({unresolvable_veth_of_in_container_nft,
                  #{key := iifname}},
                 erlkoenig_nft_container:translate_opts(
                     #{iifname => {veth_of, <<"backend">>, <<"api">>}})).

t_veth_of_oifname_errors() ->
    ?assertError({unresolvable_veth_of_in_container_nft,
                  #{key := oifname}},
                 erlkoenig_nft_container:translate_opts(
                     #{oifname => {veth_of, <<"backend">>, <<"api">>}})).

t_veth_of_oifname_ne_errors() ->
    ?assertError({unresolvable_veth_of_in_container_nft,
                  #{key := oifname_ne}},
                 erlkoenig_nft_container:translate_opts(
                     #{oifname_ne => {veth_of, <<"backend">>, <<"api">>}})).

%%%===================================================================
%%% build_batch — end-to-end binary emission
%%%===================================================================

build_batch_test_() ->
    [{"empty chains still yields a batch", fun t_empty_chains/0},
     {"single chain without rules", fun t_chain_no_rules/0},
     {"single chain with one rule", fun t_chain_one_rule/0},
     {"multiple chains in one batch", fun t_multi_chain/0},
     {"default table name is ct_container", fun t_default_table_name/0},
     {"table field is honoured by build_batch/1", fun t_table_field_name/0},
     {"custom table name is honoured", fun t_custom_table_name/0},
     {"batch atomically replaces table before adding chains", fun t_batch_replaces_table/0},
     {"combined match + protocol rule compiles", fun t_combined_match/0},
     {"unknown key in rule opts propagates", fun t_build_batch_propagates_unknown_key/0},
     {"replica_ips in rule opts propagates", fun t_build_batch_propagates_replica_ips/0}].

t_empty_chains() ->
    %% The batch still includes BEGIN + table-create + END, so it is
    %% non-empty even without any chain. Exact size varies with nft
    %% encoding, but 50 bytes is a sane floor.
    Batch = erlkoenig_nft_container:build_batch(#{chains => []}),
    ?assert(is_binary(Batch)),
    ?assert(byte_size(Batch) > 50).

t_chain_no_rules() ->
    Config = #{chains =>
                  [#{name => <<"output">>, hook => output, type => filter,
                     priority => 0, policy => accept}]},
    Batch = erlkoenig_nft_container:build_batch(Config),
    ?assert(is_binary(Batch)),
    ?assert(byte_size(Batch) > 100).

t_chain_one_rule() ->
    Config = #{chains =>
                  [#{name => <<"output">>, hook => output, type => filter,
                     priority => 0, policy => drop,
                     rules => [{accept, #{ct_state => [established]}}]}]},
    Batch = erlkoenig_nft_container:build_batch(Config),
    ?assert(is_binary(Batch)),
    ?assert(byte_size(Batch) > 150).

t_multi_chain() ->
    %% Two chains (output + input) should both encode into the same batch.
    %% A regression where only the last chain survived would show as a
    %% size smaller than two-chain-no-rules.
    OneChain = erlkoenig_nft_container:build_batch(
        #{chains => [#{name => <<"output">>, hook => output, type => filter,
                       priority => 0, policy => drop}]}),
    TwoChain = erlkoenig_nft_container:build_batch(
        #{chains => [#{name => <<"output">>, hook => output, type => filter,
                       priority => 0, policy => drop},
                     #{name => <<"input">>, hook => input, type => filter,
                       priority => 0, policy => drop}]}),
    ?assert(byte_size(TwoChain) > byte_size(OneChain)).

t_default_table_name() ->
    %% build_batch/1 picks ct_container. The table name appears as an
    %% attribute inside the NEWTABLE message — search for the literal
    %% byte sequence to confirm it was actually used.
    Batch = erlkoenig_nft_container:build_batch(#{chains => []}),
    ?assertNotEqual(nomatch, binary:match(Batch, <<"ct_container">>)).

t_table_field_name() ->
    Batch = erlkoenig_nft_container:build_batch(
        #{table => <<"ct_api_fw">>, chains => []}),
    ?assertNotEqual(nomatch, binary:match(Batch, <<"ct_api_fw">>)),
    ?assertEqual(nomatch, binary:match(Batch, <<"ct_container">>)).

t_custom_table_name() ->
    Batch = erlkoenig_nft_container:build_batch(#{chains => []},
                                                <<"ct_api_fw">>),
    ?assertNotEqual(nomatch, binary:match(Batch, <<"ct_api_fw">>)),
    ?assertEqual(nomatch, binary:match(Batch, <<"ct_container">>)).

t_batch_replaces_table() ->
    Batch = erlkoenig_nft_container:build_batch(#{chains => []}, <<"ct_api_fw">>),
    Types = nft_msg_types(Batch),
    ?assertEqual([
        ?NFNL_MSG_BATCH_BEGIN,
        nft_type(?NFT_MSG_NEWTABLE),
        nft_type(?NFT_MSG_DELTABLE),
        nft_type(?NFT_MSG_NEWTABLE),
        ?NFNL_MSG_BATCH_END
    ], Types).

t_combined_match() ->
    %% Regression guard for the compile_generic_special Co-Match bug
    %% (fixed in erlkoenig_ct_firewall — the 3-way return). If that
    %% regresses, saddr/daddr get dropped when protocol is also given.
    %% We detect it here by checking the encoded batch contains the
    %% source-IP bytes.
    Config = #{chains =>
                  [#{name => <<"output">>, hook => output, type => filter,
                     priority => 0, policy => drop,
                     rules => [{accept,
                                #{ip_saddr => {10, 50, 100, 2},
                                  ip_daddr => {10, 50, 100, 5},
                                  ip_protocol => icmp}}]}]},
    Batch = erlkoenig_nft_container:build_batch(Config),
    %% 10.50.100.2 as 4 raw bytes
    ?assertNotEqual(nomatch, binary:match(Batch, <<10, 50, 100, 2>>)),
    %% 10.50.100.5 as 4 raw bytes
    ?assertNotEqual(nomatch, binary:match(Batch, <<10, 50, 100, 5>>)).

t_build_batch_propagates_unknown_key() ->
    %% An unknown rule key must surface, even when wrapped in a full
    %% chain config — a silent drop here would defeat the SPEC-EK-023
    %% Glasbox promise.
    Config = #{chains =>
                  [#{name => <<"output">>, hook => output, type => filter,
                     priority => 0, policy => drop,
                     rules => [{accept, #{bogus_key => foo}}]}]},
    ?assertError({unknown_container_nft_rule_opt, _},
                 erlkoenig_nft_container:build_batch(Config)).

t_build_batch_propagates_replica_ips() ->
    Config = #{chains =>
                  [#{name => <<"output">>, hook => output, type => filter,
                     priority => 0, policy => drop,
                     rules => [{accept,
                                #{ip_saddr => {replica_ips, <<"p">>, <<"c">>}}}]}]},
    ?assertError({unresolvable_replica_ips_in_container_nft, _},
                 erlkoenig_nft_container:build_batch(Config)).

nft_type(MsgType) ->
    (?NFNL_SUBSYS_NFTABLES bsl 8) bor MsgType.

nft_msg_types(Bin) ->
    nft_msg_types(Bin, []).

nft_msg_types(<<>>, Acc) ->
    lists:reverse(Acc);
nft_msg_types(<<Len:32/little, Type:16/little, _Flags:16/little,
                _Seq:32/little, _Pid:32/little, _Rest/binary>> = Bin, Acc)
  when Len >= 16, byte_size(Bin) >= Len ->
    Next = align4(Len),
    <<_Msg:Next/binary, Tail/binary>> = Bin,
    nft_msg_types(Tail, [Type | Acc]).

align4(N) ->
    (N + 3) band bnot 3.
