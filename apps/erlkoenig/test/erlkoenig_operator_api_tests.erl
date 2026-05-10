%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%
%% Smoke tests for the operator-API contract boundary. These tests
%% deliberately exercise only paths that do NOT need the OTP app
%% running (argument validation, error map shape, catalog wiring,
%% exported arity). End-to-end coverage lives in integration tests.

-module(erlkoenig_operator_api_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Exported surface
%%====================================================================

exports_arity_test() ->
    {module, erlkoenig_operator_api} = code:ensure_loaded(erlkoenig_operator_api),
    Expected = [
        {quarantine_list, 0},
        {quarantine_add, 2},
        {quarantine_remove, 1},
        {admission_snapshot, 0},
        {volume_list, 0},
        {volume_list_by_container, 1},
        {volume_inspect, 1},
        {volume_destroy, 1},
        {volume_set_quota, 2},
        {volume_orphans, 0},
        {volume_gc_orphans, 1},
        {node_health, 0},
        {nft_counters, 0},
        {firewall_status, 0},
        {firewall_events, 1},
        {firewall_events_since, 3},
        {container_list, 0},
        {container_inspect, 1},
        {container_stop, 1},
        {pod_list, 0},
        {pod_list_all, 0}
    ],
    [?assert(erlang:function_exported(erlkoenig_operator_api, F, A))
     || {F, A} <- Expected],
    ok.

%%====================================================================
%% Hash validation (pure)
%%====================================================================

quarantine_add_rejects_short_hash_test() ->
    R = erlkoenig_operator_api:quarantine_add(<<"deadbeef">>, manual),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

quarantine_add_rejects_uppercase_hex_test() ->
    H = binary:copy(<<"A">>, 64),
    R = erlkoenig_operator_api:quarantine_add(H, manual),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

quarantine_add_rejects_non_binary_test() ->
    R = erlkoenig_operator_api:quarantine_add("deadbeef", manual),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

quarantine_remove_rejects_bad_hash_test() ->
    R = erlkoenig_operator_api:quarantine_remove(<<"too-short">>),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

%%====================================================================
%% Bad-arg paths for non-binary identifiers
%%====================================================================

volume_inspect_rejects_non_binary_test() ->
    R = erlkoenig_operator_api:volume_inspect(123),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

volume_destroy_rejects_non_binary_test() ->
    R = erlkoenig_operator_api:volume_destroy(123),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

volume_set_quota_rejects_non_binary_uuid_test() ->
    R = erlkoenig_operator_api:volume_set_quota(123, 0),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

volume_gc_orphans_rejects_invalid_mode_test() ->
    %% Only the argument-validation gate is unit-testable here —
    %% valid modes (dry_run / confirm) reach erlkoenig_volume_store
    %% which is a live gen_server, not available in plain eunit.
    %% The dry_run / confirm branches are exercised by the
    %% integration suite.
    R1 = erlkoenig_operator_api:volume_gc_orphans(go_for_it),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R1),
    R2 = erlkoenig_operator_api:volume_gc_orphans("dry_run"),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R2),
    R3 = erlkoenig_operator_api:volume_gc_orphans(undefined),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R3).

volume_list_by_container_rejects_non_binary_test() ->
    R = erlkoenig_operator_api:volume_list_by_container("name"),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

container_inspect_rejects_non_binary_test() ->
    R = erlkoenig_operator_api:container_inspect("id"),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

container_stop_rejects_non_binary_test() ->
    R = erlkoenig_operator_api:container_stop("id"),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

firewall_events_rejects_invalid_limit_test() ->
    R = erlkoenig_operator_api:firewall_events(0),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

firewall_events_since_rejects_invalid_args_test() ->
    R = erlkoenig_operator_api:firewall_events_since(-1, 0, 10),
    assert_error_code('EK_OPERATOR_BAD_ARGUMENT', R).

%%====================================================================
%% Error-map shape contract
%%====================================================================

bad_arg_error_map_has_required_fields_test() ->
    {error, Err} = erlkoenig_operator_api:volume_inspect(123),
    [?assert(maps:is_key(K, Err))
     || K <- [type, reason, code, context, data, severity, source, ts]],
    ?assertEqual(operator, maps:get(type, Err)),
    ?assertEqual(bad_argument, maps:get(reason, Err)),
    Data = maps:get(data, Err),
    [?assert(maps:is_key(K, Data)) || K <- [argument, value, expected]],
    ok.

%%====================================================================
%% Catalog wiring
%%====================================================================

operator_codes_in_catalog_test() ->
    [?assertMatch({ok, _}, erlkoenig_error:lookup(C))
     || C <- ['EK_OPERATOR_NOT_FOUND',
              'EK_OPERATOR_BAD_ARGUMENT',
              'EK_OPERATOR_INTERNAL']],
    ok.

%%====================================================================
%% Helpers
%%====================================================================

assert_error_code(Code, {error, #{code := Actual}}) ->
    ?assertEqual(Code, Actual);
assert_error_code(_Code, Other) ->
    erlang:error({expected_error_tuple, Other}).
