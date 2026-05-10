-module(erlkoenig_nft_firewall_tests).
-include_lib("eunit/include/eunit.hrl").

configured_ban_set_uses_explicit_ipv4_key_test() ->
    Config = #{
        ban_set => #{ipv4 => <<"ban_v4">>, ipv6 => <<"ban_v6">>},
        sets => [
            {<<"allow_custom">>, ipv4_addr},
            {<<"ban_v4">>, ipv4_addr},
            {<<"ban_v6">>, ipv6_addr}
        ]
    },
    ?assertEqual({ok, <<"ban_v4">>},
                 erlkoenig_nft_firewall:configured_ban_set(Config, <<10, 0, 0, 1>>)).

configured_ban_set_uses_explicit_ipv6_key_test() ->
    Config = #{
        ban_set => #{ipv4 => <<"ban_v4">>, ipv6 => <<"ban_v6">>},
        sets => [
            {<<"ban_v4">>, ipv4_addr},
            {<<"ban_v6">>, ipv6_addr}
        ]
    },
    ?assertEqual({ok, <<"ban_v6">>},
                 erlkoenig_nft_firewall:configured_ban_set(
                   Config, <<16#20, 16#01, 16#0d, 16#b8, 0:96>>)).

configured_ban_set_requires_key_test() ->
    Config = #{sets => [{<<"blocklist">>, ipv4_addr}]},
    ?assertEqual({error, no_ban_set_configured},
                 erlkoenig_nft_firewall:configured_ban_set(Config, <<10, 0, 0, 1>>)).

configured_ban_set_rejects_type_mismatch_test() ->
    Config = #{ban_set => #{ipv4 => <<"ban_v6">>},
               sets => [{<<"ban_v6">>, ipv6_addr}]},
    ?assertEqual({error, {ban_set_type_mismatch, <<"ban_v6">>, ipv4_addr, ipv6_addr}},
                 erlkoenig_nft_firewall:configured_ban_set(Config, <<10, 0, 0, 1>>)).

dev_default_requires_explicit_env_test() ->
    Old = os:getenv("ERLKOENIG_NFT_DEV_DEFAULT"),
    try
        os:unsetenv("ERLKOENIG_NFT_DEV_DEFAULT"),
        ?assertEqual(false, erlkoenig_nft_firewall:dev_default_enabled()),
        os:putenv("ERLKOENIG_NFT_DEV_DEFAULT", "1"),
        ?assertEqual(true, erlkoenig_nft_firewall:dev_default_enabled()),
        os:putenv("ERLKOENIG_NFT_DEV_DEFAULT", "true"),
        ?assertEqual(false, erlkoenig_nft_firewall:dev_default_enabled())
    after
        case Old of
            false -> os:unsetenv("ERLKOENIG_NFT_DEV_DEFAULT");
            Value -> os:putenv("ERLKOENIG_NFT_DEV_DEFAULT", Value)
        end
    end.

%% ============================================================
%% Phase 6d: host_table routing + §6.2 ct_state audit
%% ============================================================

host_table_returns_per_owner_table_test() ->
    ?assertEqual(<<"erlkoenig_host">>, erlkoenig_nft_firewall:host_table()).

%% Effective-config invariant: callers (init/1, reload, etc.)
%% must run normalize_config first. After it, every state /
%% runtime path that reads `table` sees the host-owner value.
%% The test exposes the normalizer through the test API to lock
%% this contract.
normalize_config_refuses_unknown_table_test() ->
    Original = #{table => <<"some_other_table">>, chains => []},
    ?assertError({unknown_nft_table, <<"some_other_table">>, _},
                 erlkoenig_nft_firewall:normalize_config(Original)).

normalize_config_inserts_table_when_missing_test() ->
    Original = #{chains => []},
    Effective = erlkoenig_nft_firewall:normalize_config(Original),
    ?assertEqual(<<"erlkoenig_host">>, maps:get(table, Effective)).

normalize_config_adds_host_observability_counters_test() ->
    Original = #{chains => [
        #{name => <<"input">>, hook => input, type => filter,
          priority => 0, policy => drop, rules => []},
        #{name => <<"output">>, hook => output, type => filter,
          priority => 0, policy => accept, rules => []}
    ]},
    Effective = erlkoenig_nft_firewall:normalize_config(Original),
    Counters = maps:get(counters, Effective),
    ?assert(lists:member(<<"input">>, Counters)),
    ?assert(lists:member(<<"output">>, Counters)),
    ?assert(lists:member(<<"dropped">>, Counters)).

observe_drop_exprs_adds_host_nflog_before_drop_test() ->
    Exprs = [
        nft_expr_ir:ip_saddr(1),
        nft_expr_ir:objref_counter(<<"banned">>),
        nft_expr_ir:drop()
    ],
    Observed = erlkoenig_nft_firewall:observe_drop_exprs(Exprs, <<"banned">>),
    ?assertMatch([
        {payload, _},
        {objref, #{type := counter, name := <<"banned">>}},
        {log, #{group := 1, prefix := <<"banned">>}},
        {immediate, #{verdict := drop}}
    ], Observed).

%% Validator: ban chain must NOT carry established,related accept.
%% The audit returns issues as a list — empty list = clean.
audit_returns_issue_for_established_in_ban_chain_test() ->
    Config = #{chains => [
        #{name => <<"prerouting_ban">>, hook => prerouting,
          priority => raw, type => filter, policy => accept,
          rules => [
              ct_established_accept,
              {set_lookup_drop, <<"blocklist">>, banned}
          ]}
    ]},
    Issues = erlkoenig_nft_firewall:validate_ct_state_audit(Config),
    ?assertEqual([{established_in_ban_chain, <<"prerouting_ban">>}], Issues).

audit_clean_ban_chain_returns_no_issues_test() ->
    Config = #{chains => [
        #{name => <<"prerouting_ban">>, hook => prerouting,
          priority => raw, type => filter, policy => accept,
          rules => [
              {set_lookup_drop, <<"blocklist">>, banned}
          ]}
    ]},
    ?assertEqual([], erlkoenig_nft_firewall:validate_ct_state_audit(Config)).

audit_recognises_generic_rule_ct_established_in_ban_chain_test() ->
    %% Production form `{rule, accept, #{ct => established}}` in
    %% the ban chain must also be flagged.
    Config = #{chains => [
        #{name => <<"prerouting_ban">>, hook => prerouting,
          priority => raw, type => filter, policy => accept,
          rules => [
              {rule, accept, #{ct => established}},
              {set_lookup_drop, <<"blocklist">>, banned}
          ]}
    ]},
    ?assertEqual([{established_in_ban_chain, <<"prerouting_ban">>}],
                 erlkoenig_nft_firewall:validate_ct_state_audit(Config)).

%% Validator: input/drop must carry the established/related
%% fast-path. (The §6.2 contract's invalid-drop half is
%% currently unenforced — DSL gap, see spec §6.2 status note.)
audit_input_chain_with_atom_fast_path_returns_no_issues_test() ->
    Config = #{chains => [
        #{name => <<"input">>, hook => input, priority => 0,
          type => filter, policy => drop,
          rules => [ct_established_accept]}
    ]},
    ?assertEqual([], erlkoenig_nft_firewall:validate_ct_state_audit(Config)).

audit_input_chain_with_generic_rule_fast_path_returns_no_issues_test() ->
    %% The reviewer's reproducer: production form via
    %% compile_generic_rule. Audit must return [].
    Config = #{chains => [
        #{name => <<"input">>, hook => input, priority => 0,
          type => filter, policy => drop,
          rules => [{rule, accept, #{ct => established}}]}
    ]},
    ?assertEqual([], erlkoenig_nft_firewall:validate_ct_state_audit(Config)).

audit_input_chain_missing_fast_path_test() ->
    Config = #{chains => [
        #{name => <<"input">>, hook => input, priority => 0,
          type => filter, policy => drop,
          rules => []}
    ]},
    Issues = erlkoenig_nft_firewall:validate_ct_state_audit(Config),
    ?assertMatch([{input_drop_missing, <<"input">>, _}], Issues),
    [{_, _, Missing}] = Issues,
    ?assertEqual([established_related_accept], Missing).

%% Phase 6e.1.c: the same fast-path contract applies to the
%% zone-owned forward base chain after 6e.1.a/6e.1.b moved the
%% writer into `erlkoenig_zone` and made regular chains the
%% policy targets.
audit_forward_chain_with_atom_fast_path_returns_no_issues_test() ->
    Config = #{chains => [
        #{name => <<"forward">>, hook => forward, priority => 0,
          type => filter, policy => drop,
          rules => [ct_established_accept]}
    ]},
    ?assertEqual([], erlkoenig_nft_firewall:validate_ct_state_audit(Config)).

audit_forward_chain_missing_fast_path_test() ->
    Config = #{chains => [
        #{name => <<"forward">>, hook => forward, priority => 0,
          type => filter, policy => drop,
          rules => []}
    ]},
    Issues = erlkoenig_nft_firewall:validate_ct_state_audit(Config),
    ?assertMatch([{input_drop_missing, <<"forward">>, _}], Issues),
    [{_, _, Missing}] = Issues,
    ?assertEqual([established_related_accept], Missing).

audit_forward_chain_flags_fast_path_after_terminal_drop_test() ->
    Config = #{chains => [
        #{name => <<"forward">>, hook => forward, priority => 0,
          type => filter, policy => drop,
          rules => [
              {rule, drop, #{saddr => <<"192.0.2.10">>}},
              ct_established_accept
          ]}
    ]},
    Issues = erlkoenig_nft_firewall:validate_ct_state_audit(Config),
    ?assertMatch([{input_drop_missing, <<"forward">>, _}], Issues),
    [{_, _, Missing}] = Issues,
    ?assert(lists:member(established_related_accept_must_be_early, Missing)).

%% Non-production rule shapes (legacy 3-tuples,
%% `#{ct_state := ...}` maps) MUST NOT be recognised as a
%% fast-path — the production builder does not compile them
%% into a working ct-state match, so accepting them in the
%% audit would let the validator say "clean" while the runtime
%% installs an unmatched accept.
audit_does_not_recognise_legacy_ct_state_tuple_test() ->
    Config = #{chains => [
        #{name => <<"input">>, hook => input, priority => 0,
          type => filter, policy => drop,
          rules => [{ct_state, [established, related], accept}]}
    ]},
    Issues = erlkoenig_nft_firewall:validate_ct_state_audit(Config),
    ?assertMatch([{input_drop_missing, <<"input">>, _}], Issues),
    [{_, _, Missing}] = Issues,
    ?assert(lists:member(established_related_accept, Missing)).

audit_does_not_recognise_ct_state_map_form_test() ->
    Config = #{chains => [
        #{name => <<"input">>, hook => input, priority => 0,
          type => filter, policy => drop,
          rules => [{rule, accept, #{ct_state => [established, related]}}]}
    ]},
    Issues = erlkoenig_nft_firewall:validate_ct_state_audit(Config),
    ?assertMatch([{input_drop_missing, <<"input">>, _}], Issues),
    [{_, _, Missing}] = Issues,
    ?assert(lists:member(established_related_accept, Missing)).

%% "Early" position check still applies. Established/related
%% accept must come before any non-audit terminal drop/reject.
audit_flags_fast_path_after_terminal_drop_test() ->
    Config = #{chains => [
        #{name => <<"input">>, hook => input, priority => 0,
          type => filter, policy => drop,
          rules => [
              drop,
              ct_established_accept
          ]}
    ]},
    Issues = erlkoenig_nft_firewall:validate_ct_state_audit(Config),
    ?assertMatch([{input_drop_missing, <<"input">>, _}], Issues),
    [{_, _, Missing}] = Issues,
    ?assert(lists:member(established_related_accept_must_be_early, Missing)).

audit_flags_fast_path_after_generic_rule_drop_test() ->
    Config = #{chains => [
        #{name => <<"input">>, hook => input, priority => 0,
          type => filter, policy => drop,
          rules => [
              {rule, drop, #{saddr => <<"192.0.2.5">>}},
              {rule, accept, #{ct => established}}
          ]}
    ]},
    Issues = erlkoenig_nft_firewall:validate_ct_state_audit(Config),
    ?assertMatch([{input_drop_missing, <<"input">>, _}], Issues),
    [{_, _, Missing}] = Issues,
    ?assert(lists:member(established_related_accept_must_be_early, Missing)).

audit_generic_rule_accept_does_not_block_fast_path_test() ->
    %% A non-fast-path accept (e.g. allow lo) before the
    %% fast-path must NOT disqualify the established/related
    %% accept that follows. Only drop/reject are terminal.
    Config = #{chains => [
        #{name => <<"input">>, hook => input, priority => 0,
          type => filter, policy => drop,
          rules => [
              {rule, accept, #{iif => <<"lo">>}},
              {rule, accept, #{ct => established}}
          ]}
    ]},
    ?assertEqual([], erlkoenig_nft_firewall:validate_ct_state_audit(Config)).

audit_skips_input_with_accept_policy_test() ->
    Config = #{chains => [
        #{name => <<"input">>, hook => input, priority => 0,
          type => filter, policy => accept, rules => []}
    ]},
    ?assertEqual([], erlkoenig_nft_firewall:validate_ct_state_audit(Config)).
