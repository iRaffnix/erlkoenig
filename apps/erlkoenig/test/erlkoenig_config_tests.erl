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

validate_missing_file_test() ->
    ?assertMatch({error, {read_failed, _, _}},
                 erlkoenig_config:validate("/tmp/erlkoenig_nonexistent_42.term")).

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
    [Resolved] = erlkoenig_config:resolve_host_refs(Rule, Ctx),
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
    Resolved = erlkoenig_config:resolve_host_refs(Rule, Ctx),
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
    Resolved = erlkoenig_config:resolve_host_refs(Rule, Ctx),
    %% 2 web replicas × 1 app replica = 2 rules
    ?assertEqual(2, length(Resolved)),
    lists:foreach(fun(R) ->
        #{saddr := _, daddr := {10, 0, 1, 2, 32}} = element(3, R)
    end, Resolved).

%% Non-pod refs pass through unchanged
resolve_plain_interface_test() ->
    Ctx = #{ip_map => #{}, bridge => <<"br0">>},
    Rule = {rule, accept, #{iif => <<"eth0">>, tcp => 22}},
    [Resolved] = erlkoenig_config:resolve_host_refs(Rule, Ctx),
    ?assertEqual(Rule, Resolved).

%% Bridge ref resolves to bridge name
resolve_bridge_ref_test() ->
    Ctx = #{ip_map => #{}, bridge => <<"dmz">>},
    Rule = {rule, accept, #{iif => bridge, oif => <<"eth0">>}},
    [Resolved] = erlkoenig_config:resolve_host_refs(Rule, Ctx),
    ?assertMatch({rule, accept, #{iif := <<"dmz">>, oif := <<"eth0">>}}, Resolved).

%% Unknown pod ref: no match in IpMap, keeps original name
resolve_unknown_pod_ref_test() ->
    Ctx = #{ip_map => #{}, bridge => <<"br0">>},
    Rule = {rule, accept, #{oif => <<"unknown.service">>}},
    [Resolved] = erlkoenig_config:resolve_host_refs(Rule, Ctx),
    ?assertMatch({rule, accept, #{oif := <<"unknown.service">>}}, Resolved).

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
    WorkerIps = lists:sort(erlkoenig_config:find_all_replica_ips(<<"worker">>, <<"fn">>, IpMap)),
    ?assertEqual([{10, 0, 1, 2}, {10, 0, 1, 3}, {10, 0, 1, 4}, {10, 0, 1, 12}], WorkerIps),
    GatewayIps = erlkoenig_config:find_all_replica_ips(<<"gateway">>, <<"proxy">>, IpMap),
    ?assertEqual([{10, 0, 0, 2}], GatewayIps),
    EmptyIps = erlkoenig_config:find_all_replica_ips(<<"missing">>, <<"pod">>, IpMap),
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
    Resolved = erlkoenig_config:resolve_host_refs(Rule, Ctx),
    ?assertEqual(5, length(Resolved)),

    %% Each rule has the gateway as saddr and a different worker as daddr
    Saddrs = lists:usort([maps:get(saddr, element(3, R)) || R <- Resolved]),
    ?assertEqual([{10, 0, 0, 2, 32}], Saddrs),
    Daddrs = lists:sort([maps:get(daddr, element(3, R)) || R <- Resolved]),
    ?assertEqual([{10, 0, 1, 2, 32}, {10, 0, 1, 3, 32}, {10, 0, 1, 4, 32},
                  {10, 0, 1, 5, 32}, {10, 0, 1, 6, 32}], Daddrs).

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
