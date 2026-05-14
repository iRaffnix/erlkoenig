%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_ct_opts_tests).

-include_lib("eunit/include/eunit.hrl").
-include("erlkoenig_ct_state.hrl").

binary_quarantined_never_restarts_test() ->
    Data = #ct_data{
        restart = always,
        error_reason = #{code => 'EK_RUNTIME_BINARY_QUARANTINED'}
    },
    ?assertEqual(false, erlkoenig_ct_opts:should_restart(Data)).

binary_quarantined_pod_exit_is_shutdown_test() ->
    Data = #ct_data{
        error_reason = #{code => 'EK_RUNTIME_BINARY_QUARANTINED'}
    },
    ?assertEqual(shutdown, erlkoenig_ct_opts:pod_exit_reason(Data)).

signal_exit_still_restarts_on_failure_test() ->
    Data = #ct_data{
        restart = on_failure,
        exit_info = #{exit_code => 139, term_signal => 11}
    },
    ?assertEqual(true, erlkoenig_ct_opts:should_restart(Data)).

terminal_signal_exit_records_crash_for_quarantine_test() ->
    Data = #ct_data{
        restart = no_restart,
        exit_info = #{exit_code => -1, term_signal => 11}
    },
    ?assertEqual(true, erlkoenig_ct:should_record_terminal_crash(Data, false)).

terminal_clean_exit_does_not_record_crash_test() ->
    Data = #ct_data{
        restart = no_restart,
        exit_info = #{exit_code => 0, term_signal => 0}
    },
    ?assertEqual(false, erlkoenig_ct:should_record_terminal_crash(Data, false)).

restarting_path_does_not_record_terminal_crash_twice_test() ->
    Data = #ct_data{
        restart = on_failure,
        exit_info = #{exit_code => -1, term_signal => 11}
    },
    ?assertEqual(false, erlkoenig_ct:should_record_terminal_crash(Data, true)).

quarantine_refusal_does_not_feed_back_into_crash_counter_test() ->
    Data = #ct_data{
        restart = no_restart,
        exit_info = #{exit_code => -1, term_signal => 11},
        error_reason = #{code => 'EK_RUNTIME_BINARY_QUARANTINED'}
    },
    ?assertEqual(false, erlkoenig_ct:should_record_terminal_crash(Data, false)).

restart_cleanup_success_clears_net_info_test() ->
    Data = #ct_data{net_info = #{iface => <<"i.web">>}},
    ?assertMatch({ok, #ct_data{net_info = undefined}},
                 erlkoenig_ct:restart_cleanup_result(Data, ok, ok)).

restart_cleanup_network_failure_keeps_net_info_test() ->
    Data = #ct_data{net_info = #{iface => <<"i.web">>}},
    ?assertMatch(
       {error, {network_teardown_failed, ebusy},
        #ct_data{net_info = #{iface := <<"i.web">>}}},
       erlkoenig_ct:restart_cleanup_result(Data, {error, ebusy}, ok)).

restart_cleanup_cgroup_failure_keeps_net_info_test() ->
    Data = #ct_data{net_info = #{iface => <<"i.web">>}},
    ?assertMatch(
       {error, {cgroup_destroy_failed, eperm},
        #ct_data{net_info = #{iface := <<"i.web">>}}},
       erlkoenig_ct:restart_cleanup_result(Data, ok, {error, eperm})).

restart_cleanup_unexpected_network_result_fails_test() ->
    Data = #ct_data{net_info = #{iface => <<"i.web">>}},
    ?assertMatch(
       {error, {network_teardown_failed, timeout},
        #ct_data{net_info = #{iface := <<"i.web">>}}},
       erlkoenig_ct:restart_cleanup_result(Data, timeout, ok)).

restart_cleanup_unexpected_cgroup_result_fails_test() ->
    Data = #ct_data{net_info = #{iface => <<"i.web">>}},
    ?assertMatch(
       {error, {cgroup_destroy_failed, ignored},
        #ct_data{net_info = #{iface := <<"i.web">>}}},
       erlkoenig_ct:restart_cleanup_result(Data, ok, ignored)).
