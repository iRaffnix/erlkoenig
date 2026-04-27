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
