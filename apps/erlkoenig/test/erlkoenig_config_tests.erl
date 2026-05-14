%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_config (DSL config loader).
%%%
%%% Tests parse/1, validate/1 and internal helpers without requiring
%%% a running Erlkoenig instance. Uses temporary files for parse tests.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_config_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% =================================================================
%% parse/1 -- Term file reading
%% =================================================================

parse_map_format_test() ->
    File = write_term_file(#{containers => []}),
    ?assertMatch({ok, #{containers := []}}, erlkoenig_config:parse(File)),
    file:delete(File).

parse_list_format_test() ->
    File = write_term_file([{containers, [#{name => "web", binary => "/bin/web"}]}]),
    {ok, Result} = erlkoenig_config:parse(File),
    ?assert(is_map(Result)),
    ?assertMatch(#{containers := _}, Result),
    file:delete(File).

parse_invalid_format_test() ->
    %% Multiple top-level terms are invalid
    File = tmp_path(),
    ok = file:write_file(File, "one.\ntwo.\n"),
    ?assertMatch({error, {invalid_format, _}}, erlkoenig_config:parse(File)),
    file:delete(File).

parse_missing_file_test() ->
    ?assertMatch({error, {read_failed, _, _}},
                 erlkoenig_config:parse("/tmp/erlkoenig_nonexistent_42.term")).

%% =================================================================
%% validate/1 -- Config structure validation
%% =================================================================

validate_valid_string_names_test() ->
    File = write_term_file(#{containers => [
        #{name => "web", binary => "/bin/web"},
        #{name => "api", binary => "/bin/api"}
    ]}),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

validate_valid_binary_names_test() ->
    File = write_term_file(#{containers => [
        #{name => <<"web">>, binary => <<"/bin/web">>}
    ]}),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

validate_no_containers_test() ->
    %% Config without containers key is valid (may only have watches/guard)
    File = write_term_file(#{watches => []}),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

validate_containers_not_list_test() ->
    File = write_term_file(#{containers => not_a_list}),
    ?assertMatch({error, {invalid_type, containers, expected_list}},
                 erlkoenig_config:validate(File)),
    file:delete(File).

validate_invalid_container_test() ->
    File = write_term_file(#{containers => [#{bad => true}]}),
    ?assertMatch({error, {invalid_container, _}},
                 erlkoenig_config:validate(File)),
    file:delete(File).

validate_rejects_container_memory_above_aggregate_ceiling_test() ->
    with_resource_protection(
      #{containers_memory_max => 209_715_200, containers_pids_max => 1024},
      fun() ->
          File = write_term_file(#{containers => [
              #{name => <<"api">>, binary => <<"/bin/api">>,
                limits => #{memory => 314_572_800}}
          ]}),
          ?assertMatch({error, {container_limit_exceeds_ceiling,
                                #{container := <<"api">>, limit := memory,
                                  value := 314_572_800,
                                  ceiling := 209_715_200}}},
                       erlkoenig_config:validate(File)),
          file:delete(File)
      end).

validate_rejects_memory_total_above_aggregate_ceiling_test() ->
    with_resource_protection(
      #{containers_memory_max => 314_572_800, containers_pids_max => 1024},
      fun() ->
          File = write_term_file(#{containers => [
              #{name => <<"api">>, binary => <<"/bin/api">>,
                limits => #{memory => 157_286_400}, replicas => 2},
              #{name => <<"worker">>, binary => <<"/bin/worker">>,
                limits => #{memory => 52_428_800}}
          ]}),
          ?assertMatch({error, {container_limit_total_exceeds_ceiling,
                                #{limit := memory, total := 367_001_600,
                                  ceiling := 314_572_800}}},
                       erlkoenig_config:validate(File)),
          file:delete(File)
      end).

validate_rejects_pids_total_above_aggregate_ceiling_test() ->
    with_resource_protection(
      #{containers_memory_max => 134_217_728, containers_pids_max => 10},
      fun() ->
          File = write_term_file(#{pods => [
              #{name => <<"p">>, containers => [
                  #{name => <<"api">>, binary => <<"/bin/api">>,
                    limits => #{pids => 6}},
                  #{name => <<"worker">>, binary => <<"/bin/worker">>,
                    limits => #{pids => 5}}
              ]}
          ]}),
          ?assertMatch({error, {container_limit_total_exceeds_ceiling,
                                #{limit := pids, total := 11,
                                  ceiling := 10}}},
                       erlkoenig_config:validate(File)),
          file:delete(File)
      end).

validate_rejects_cpu_outside_one_core_percent_range_test() ->
    with_resource_protection(
      #{containers_memory_max => 134_217_728, containers_pids_max => 1024},
      fun() ->
          File = write_term_file(#{containers => [
              #{name => <<"api">>, binary => <<"/bin/api">>,
                limits => #{cpu => 125}}
          ]}),
          ?assertMatch({error, {invalid_container_limit,
                                #{container := <<"api">>, limit := cpu,
                                  value := 125}}},
                       erlkoenig_config:validate(File)),
          file:delete(File)
      end).

validate_missing_file_test() ->
    ?assertMatch({error, {read_failed, _, _}},
                 erlkoenig_config:validate("/tmp/erlkoenig_nonexistent_42.term")).

validate_zone_with_legacy_deployments_refused_test() ->
    %% Post-6k: zone-level `deployments' is the pre-pod replica
    %% shape and must be refused at the validator. Operator note in
    %% §8.1 covers the manual rewrite to inline `zone:`+`replicas:`
    %% on each container.
    File = write_term_file(#{containers => [],
                             zones => [#{name => <<"z">>,
                                         deployments => [#{pod => <<"p">>,
                                                           replicas => 2}]}]}),
    ?assertMatch({error, {legacy_zone_shape_refused,
                          #{zone := <<"z">>, field := deployments}}},
                 erlkoenig_config:validate(File)),
    file:delete(File).

validate_zone_with_legacy_containers_refused_test() ->
    %% Post-6k: zone-level `containers' is the pre-pod shape (raw
    %% containers parented by a zone) and must be refused. The
    %% current DSL parents containers under a pod and routes them
    %% to a zone via the container's own `zone:` field.
    File = write_term_file(#{containers => [],
                             zones => [#{name => <<"z">>,
                                         containers => [#{name => <<"c">>,
                                                          binary => <<"b">>}]}]}),
    ?assertMatch({error, {legacy_zone_shape_refused,
                          #{zone := <<"z">>, field := containers}}},
                 erlkoenig_config:validate(File)),
    file:delete(File).

validate_zone_with_legacy_bridge_refused_test() ->
    File = write_term_file(#{containers => [],
                             zones => [#{name => <<"z">>,
                                         bridge => <<"ek_br_z">>}]}),
    ?assertMatch({error, {legacy_zone_shape_refused,
                          #{zone := <<"z">>, field := bridge}}},
                 erlkoenig_config:validate(File)),
    file:delete(File).

validate_zone_with_legacy_allows_refused_test() ->
    File = write_term_file(#{containers => [],
                             zones => [#{name => <<"z">>,
                                         allows => [dns]}]}),
    ?assertMatch({error, {legacy_zone_shape_refused,
                          #{zone := <<"z">>, field := allows}}},
                 erlkoenig_config:validate(File)),
    file:delete(File).

expand_container_replicas_refuses_undeclared_zone_test() ->
    ?assertError(
        {undeclared_zone, <<"missing">>, <<"api">>},
        erlkoenig_config_flatten:expand_container_replicas(
            <<"pod">>,
            #{name => <<"api">>, zone => <<"missing">>, replicas => 1},
            #{<<"known">> => {10, 1, 0}},
            #{}
        )
    ).

%% =================================================================
%% watches
%% =================================================================

watch_config_defaults_to_host_owner_table_test() ->
    Watch = #{counters => [<<"input">>, <<"dropped">>], actions => []},
    ?assertEqual(
       #{family => 1,
         table => <<"erlkoenig_host">>,
         counters => [<<"input">>, <<"dropped">>],
         interval => 2000},
       erlkoenig_config:watch_config(Watch)).

watch_config_honors_explicit_table_test() ->
    Watch = #{table => <<"custom_table">>, family => 2,
              counters => [<<"drops">>], interval => 5000,
              actions => []},
    ?assertEqual(
       #{family => 2,
         table => <<"custom_table">>,
         counters => [<<"drops">>],
         interval => 5000},
       erlkoenig_config:watch_config(Watch)).

%% =================================================================
%% build_spawn_opts (internal, tested indirectly via module export)
%% =================================================================

%% build_spawn_opts is not exported, so we test the contract:
%% known keys are copied, unknown keys are ignored.
%% We do this by testing container_names and the validate pipeline.

container_names_extraction_test() ->
    %% container_names/1 extracts binary names from config
    Config = #{containers => [
        #{name => "alpha", binary => "/a"},
        #{name => <<"beta">>, binary => <<"/b">>},
        #{name => "gamma", binary => "/c"}
    ]},
    %% We can't call container_names directly (not exported),
    %% but we can verify the validate pipeline accepts this.
    File = write_term_file(Config),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

container_names_empty_test() ->
    Config = #{},
    File = write_term_file(Config),
    ?assertEqual(ok, erlkoenig_config:validate(File)),
    file:delete(File).

%% =================================================================
%% resolve_host_refs -- Pod-qualified name expansion
%% =================================================================

%% Single replica: "web.nginx" resolves to one rule with IP
resolve_single_replica_test() ->
    IpMap = #{<<"web-0-nginx">> => {10, 0, 0, 2}},
    Ctx = #{ip_map => IpMap, bridge => <<"br0">>},
    Rule = {rule, accept, #{iif => <<"eth0">>, oif => <<"web.nginx">>, tcp => 8443}},
    [Resolved] = erlkoenig_config_nft:resolve_host_refs(Rule, Ctx),
    ?assertMatch({rule, accept, #{daddr := {10, 0, 0, 2, 32}, tcp := 8443}}, Resolved),
    %% iif stays as interface name
    #{iif := <<"eth0">>} = element(3, Resolved).

%% Multiple replicas: "worker.fn" with 3 replicas produces 3 rules
resolve_multi_replica_test() ->
    IpMap = #{
        <<"worker-0-fn">> => {10, 0, 1, 2},
        <<"worker-1-fn">> => {10, 0, 1, 3},
        <<"worker-2-fn">> => {10, 0, 1, 4}
    },
    Ctx = #{ip_map => IpMap, bridge => <<"compute">>},
    Rule = {rule, accept, #{iif => <<"gateway.proxy">>, oif => <<"worker.fn">>, tcp => 9000}},
    %% gateway.proxy not in IpMap → stays as iif name
    %% worker.fn has 3 replicas → 3 rules
    Resolved = erlkoenig_config_nft:resolve_host_refs(Rule, Ctx),
    ?assertEqual(3, length(Resolved)),
    Daddrs = lists:sort([maps:get(daddr, element(3, R)) || R <- Resolved]),
    ?assertEqual([{10, 0, 1, 2, 32}, {10, 0, 1, 3, 32}, {10, 0, 1, 4, 32}], Daddrs),
    %% All rules keep the tcp port
    lists:foreach(fun(R) ->
        ?assertMatch({rule, accept, #{tcp := 9000}}, R)
    end, Resolved).

%% Both iif and oif are pod-qualified: cartesian product
resolve_both_pod_refs_test() ->
    IpMap = #{
        <<"web-0-nginx">> => {10, 0, 0, 2},
        <<"web-1-nginx">> => {10, 0, 0, 3},
        <<"app-0-api">> => {10, 0, 1, 2}
    },
    Ctx = #{ip_map => IpMap, bridge => <<"br0">>},
    Rule = {rule, accept, #{iif => <<"web.nginx">>, oif => <<"app.api">>, tcp => 4000}},
    Resolved = erlkoenig_config_nft:resolve_host_refs(Rule, Ctx),
    %% 2 web replicas × 1 app replica = 2 rules
    ?assertEqual(2, length(Resolved)),
    lists:foreach(fun(R) ->
        #{saddr := _, daddr := {10, 0, 1, 2, 32}} = element(3, R)
    end, Resolved).

expand_pod_ref_rules_refuses_unrepresentable_ref_count_test() ->
    ?assertError(
        {too_many_pod_refs, accept, #{tcp := 443}, _},
        erlkoenig_config_nft:expand_pod_ref_rules(
            accept,
            #{tcp => 443},
            [
                {saddr, [{10, 0, 0, 2}]},
                {daddr, [{10, 0, 1, 2}]},
                {extra, [{10, 0, 2, 2}]}
            ]
        )
    ).

%% Non-pod refs pass through unchanged
resolve_plain_interface_test() ->
    Ctx = #{ip_map => #{}, bridge => <<"br0">>},
    Rule = {rule, accept, #{iif => <<"eth0">>, tcp => 22}},
    [Resolved] = erlkoenig_config_nft:resolve_host_refs(Rule, Ctx),
    ?assertEqual(Rule, Resolved).

%% Legacy bridge shortcut is refused under IPVLAN.
resolve_legacy_bridge_ref_refused_test() ->
    Ctx = #{ip_map => #{}, bridge => <<"dmz">>},
    ?assertError({legacy_bridge_ref_refused, #{field := iif}},
        erlkoenig_config_nft:resolve_host_refs(
            {rule, accept, #{iif => bridge, oif => <<"eth0">>}}, Ctx)),
    ?assertError({legacy_bridge_ref_refused, #{field := oif}},
        erlkoenig_config_nft:resolve_host_refs(
            {rule, accept, #{oif => bridge, iif => <<"eth0">>}}, Ctx)).

%% Unknown pod ref: no match in IpMap, keeps original name
resolve_unknown_pod_ref_test() ->
    Ctx = #{ip_map => #{}, bridge => <<"br0">>},
    Rule = {rule, accept, #{oif => <<"unknown.service">>}},
    [Resolved] = erlkoenig_config_nft:resolve_host_refs(Rule, Ctx),
    ?assertMatch({rule, accept, #{oif := <<"unknown.service">>}}, Resolved).

%% Legacy host-interface wildcard is refused under IPVLAN.
resolve_legacy_containers_ref_refused_test() ->
    Ctx = #{ip_map => #{}, bridge => <<"br0">>},
    ?assertError({legacy_containers_ref_refused, #{field := oif}},
        erlkoenig_config_nft:resolve_host_refs(
            {rule, accept, #{oif => containers}}, Ctx)),
    ?assertError({legacy_containers_ref_refused, #{field := iif}},
        erlkoenig_config_nft:resolve_host_refs(
            {rule, accept, #{iif => containers}}, Ctx)).

%% find_all_replica_ips finds all matching replicas
find_all_replica_ips_test() ->
    IpMap = #{
        <<"worker-0-fn">> => {10, 0, 1, 2},
        <<"worker-1-fn">> => {10, 0, 1, 3},
        <<"worker-2-fn">> => {10, 0, 1, 4},
        <<"worker-10-fn">> => {10, 0, 1, 12},
        <<"gateway-0-proxy">> => {10, 0, 0, 2},
        <<"other-0-fn">> => {10, 0, 2, 2}
    },
    WorkerIps = lists:sort(erlkoenig_config_nft:find_all_replica_ips(<<"worker">>, <<"fn">>, IpMap)),
    ?assertEqual([{10, 0, 1, 2}, {10, 0, 1, 3}, {10, 0, 1, 4}, {10, 0, 1, 12}], WorkerIps),
    GatewayIps = erlkoenig_config_nft:find_all_replica_ips(<<"gateway">>, <<"proxy">>, IpMap),
    ?assertEqual([{10, 0, 0, 2}], GatewayIps),
    EmptyIps = erlkoenig_config_nft:find_all_replica_ips(<<"missing">>, <<"pod">>, IpMap),
    ?assertEqual([], EmptyIps).

%% Lambda pattern: 1 gateway + 5 workers, full forward chain expansion
lambda_pattern_resolve_test() ->
    IpMap = #{
        <<"gateway-0-proxy">> => {10, 0, 0, 2},
        <<"worker-0-fn">> => {10, 0, 1, 2},
        <<"worker-1-fn">> => {10, 0, 1, 3},
        <<"worker-2-fn">> => {10, 0, 1, 4},
        <<"worker-3-fn">> => {10, 0, 1, 5},
        <<"worker-4-fn">> => {10, 0, 1, 6}
    },
    Ctx = #{ip_map => IpMap, bridge => <<"edge">>},

    %% Rule: gateway.proxy → worker.fn = 1 × 5 = 5 rules
    Rule = {rule, accept, #{iif => <<"gateway.proxy">>, oif => <<"worker.fn">>, tcp => 9000}},
    Resolved = erlkoenig_config_nft:resolve_host_refs(Rule, Ctx),
    ?assertEqual(5, length(Resolved)),

    %% Each rule has the gateway as saddr and a different worker as daddr
    Saddrs = lists:usort([maps:get(saddr, element(3, R)) || R <- Resolved]),
    ?assertEqual([{10, 0, 0, 2, 32}], Saddrs),
    Daddrs = lists:sort([maps:get(daddr, element(3, R)) || R <- Resolved]),
    ?assertEqual([{10, 0, 1, 2, 32}, {10, 0, 1, 3, 32}, {10, 0, 1, 4, 32},
                  {10, 0, 1, 5, 32}, {10, 0, 1, 6, 32}], Daddrs).

%% =================================================================
%% expand_nft_rule/4 -- translation seam (Muster 9: clause ordering)
%% =================================================================

expand_veth_of_refused_iifname_test() ->
    %% Post-6i: {veth_of, _, _} is fail-loud at expansion time
    %% before any legacy host-interface resolver can invent truth.
    %% IPVLAN slaves are not visible on the host, so the old resolver produced
    %% no kernel-effective rule. Refusal at the seam beats silent
    %% no-op.
    ?assertError({legacy_veth_of_refused, #{pod := <<"pod1">>,
                                            container := <<"api">>}},
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{iifname => {veth_of, <<"pod1">>, <<"api">>}},
            #{}, #{})).

expand_veth_of_refused_oifname_test() ->
    ?assertError({legacy_veth_of_refused, #{pod := <<"pod1">>,
                                            container := <<"api">>}},
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{oifname => {veth_of, <<"pod1">>, <<"api">>}},
            #{}, #{})).

expand_veth_of_refused_oifname_ne_test() ->
    ?assertError({legacy_veth_of_refused, #{pod := <<"pod1">>,
                                            container := <<"api">>}},
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{oifname_ne => {veth_of, <<"pod1">>, <<"api">>}},
            #{}, #{})).

expand_plain_iif_name_binary_test() ->
    %% Non-veth_of values still pass through the generic clauses.
    [{rule, accept, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{iifname => <<"eth0">>},
            #{}, #{}),
    ?assertEqual(<<"eth0">>, maps:get(iif, Opts)).

expand_plain_oif_name_binary_test() ->
    [{rule, accept, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{oifname => <<"eth0">>},
            #{}, #{}),
    ?assertEqual(<<"eth0">>, maps:get(oif, Opts)).

expand_ip_saddr_4tuple_adds_prefix_32_test() ->
    %% 4-tuple is shorthand for a host route — translator must add /32
    %% before compile_generic_rule sees it; otherwise the rule gets
    %% compiled without a subnet and the kernel rejects / silently
    %% widens. Catch here before the batch hits the wire.
    [{rule, accept, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{ip_saddr => {10, 0, 0, 1}},
            #{}, #{}),
    ?assertEqual({10, 0, 0, 1, 32}, maps:get(saddr, Opts)).

expand_ip_daddr_5tuple_keeps_prefix_test() ->
    [{rule, accept, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{ip_daddr => {10, 0, 0, 0, 24}},
            #{}, #{}),
    ?assertEqual({10, 0, 0, 0, 24}, maps:get(daddr, Opts)).

expand_replica_ips_refuses_empty_saddr_targets_test() ->
    ?assertError({unresolved_replica_ips,
                  #{field := saddr, pod := <<"worker">>,
                    container := <<"fn">>}},
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{ip_saddr => {replica_ips, <<"worker">>, <<"fn">>},
              tcp_dport => 9000},
            #{}, #{})).

expand_replica_ips_refuses_empty_daddr_targets_test() ->
    ?assertError({unresolved_replica_ips,
                  #{field := daddr, pod := <<"worker">>,
                    container := <<"fn">>}},
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{ip_daddr => {replica_ips, <<"worker">>, <<"fn">>},
              tcp_dport => 9000},
            #{}, #{})).

expand_ct_state_takes_head_test() ->
    %% The DSL lets operators write `ct_state: [:established, :related]`
    %% — we only keep the head today. Pin the behaviour so a future
    %% change to combine states is a deliberate signal.
    [{rule, accept, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{ct_state => [established, related]},
            #{}, #{}),
    ?assertEqual(established, maps:get(ct, Opts)).

expand_counter_normalised_to_binary_test() ->
    [{rule, accept, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(accept,
            #{counter => "inbound"},
            #{}, #{}),
    ?assertEqual(<<"inbound">>, maps:get(counter, Opts)).

%% =================================================================
%% jump verdict — preserves match/modifier opts (was silently dropped)
%% =================================================================

expand_jump_preserves_tcp_dport_test() ->
    %% Regression: an operator-declared `jump to: chain, tcp_dport: 80`
    %% used to collapse into an unconditional `jump chain` — the kernel
    %% rule matched ALL traffic. That's a Glasbox-breaking security
    %% widening. The match must survive expansion.
    [{rule, jump, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(jump,
            #{to => <<"target">>, tcp_dport => 80},
            #{}, #{}),
    ?assertEqual(<<"target">>, maps:get(chain, Opts)),
    ?assertEqual(80, maps:get(tcp, Opts)).

expand_jump_preserves_counter_test() ->
    [{rule, jump, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(jump,
            #{to => <<"target">>, counter => <<"jumped">>},
            #{}, #{}),
    ?assertEqual(<<"jumped">>, maps:get(counter, Opts)).

expand_jump_preserves_ip_saddr_test() ->
    [{rule, jump, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(jump,
            #{to => <<"target">>, ip_saddr => {10, 0, 0, 1}},
            #{}, #{}),
    ?assertEqual({10, 0, 0, 1, 32}, maps:get(saddr, Opts)).

expand_jump_preserves_multiple_matches_test() ->
    %% A realistic rule: jump to threat_chain for a specific source,
    %% destination port, with a named counter.
    [{rule, jump, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(jump,
            #{to => <<"threat_chain">>,
              ip_saddr => {10, 0, 0, 1},
              tcp_dport => 22,
              counter => "ssh_attempts"},
            #{}, #{}),
    ?assertEqual(<<"threat_chain">>, maps:get(chain, Opts)),
    ?assertEqual({10, 0, 0, 1, 32}, maps:get(saddr, Opts)),
    ?assertEqual(22, maps:get(tcp, Opts)),
    ?assertEqual(<<"ssh_attempts">>, maps:get(counter, Opts)).

expand_jump_refuses_iifname_veth_of_test() ->
    %% Post-6i: jump rules carrying a {veth_of, _, _} iifname must
    %% bubble the refusal from the generic clause; the jump path
    %% delegates to the generic expander, so the refusal arm there
    %% covers this case too.
    ?assertError({legacy_veth_of_refused, _},
        erlkoenig_config_nft:expand_nft_rule(jump,
            #{to => <<"target">>,
              iifname => {veth_of, <<"pod1">>, <<"api">>}},
            #{}, #{})).

expand_jump_bare_no_matches_test() ->
    %% A jump with no matches still produces a valid rule — just
    %% `jump chain` with no other opts.
    [{rule, jump, Opts}] =
        erlkoenig_config_nft:expand_nft_rule(jump,
            #{to => <<"target">>},
            #{}, #{}),
    ?assertEqual(<<"target">>, maps:get(chain, Opts)),
    ?assertEqual(1, map_size(Opts)).

%% =================================================================
%% Helpers
%% =================================================================

tmp_path() ->
    "/tmp/erlkoenig_config_test_" ++
        integer_to_list(erlang:unique_integer([positive])) ++ ".term".

write_term_file(Term) ->
    Path = tmp_path(),
    Data = io_lib:format("~tp.~n", [Term]),
    ok = file:write_file(Path, Data),
    Path.

with_resource_protection(Override, Fun) ->
    Previous = application:get_env(erlkoenig, resource_protection),
    Cfg = #{mode => development,
            containers_memory_max => 1_073_741_824,
            containers_pids_max => 24576},
    application:set_env(erlkoenig, resource_protection, maps:merge(Cfg, Override)),
    try Fun()
    after
        case Previous of
            undefined -> application:unset_env(erlkoenig, resource_protection);
            {ok, Old} -> application:set_env(erlkoenig, resource_protection, Old)
        end
    end.
