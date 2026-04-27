%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_ct_info_tests).

-include_lib("eunit/include/eunit.hrl").
-include("erlkoenig_ct_state.hrl").

stopped_clean_exit_stays_stopped_test() ->
    Info = erlkoenig_ct_info:build_info(stopped, base_data(#{
        exit_code => 0,
        term_signal => 0
    })),
    ?assertEqual(stopped, maps:get(state, Info)),
    ?assertEqual(#{exit_code => 0, term_signal => 0},
                 maps:get(exit_info, Info)).

stopped_signal_exit_projects_failed_test() ->
    Info = erlkoenig_ct_info:build_info(stopped, base_data(#{
        exit_code => 139,
        term_signal => 11
    })),
    ?assertEqual(failed, maps:get(state, Info)),
    ?assertEqual(#{exit_code => 139, term_signal => 11},
                 maps:get(exit_info, Info)).

stopped_user_stop_remains_stopped_even_with_signal_test() ->
    Info = erlkoenig_ct_info:build_info(stopped, (base_data(#{
        exit_code => 137,
        term_signal => 9
    }))#ct_data{user_stopped = true}),
    ?assertEqual(stopped, maps:get(state, Info)).

base_data(ExitInfo) ->
    #ct_data{
        id = <<"ct-test">>,
        binary_path = <<"/bin/test">>,
        name = <<"ct-test">>,
        exit_info = ExitInfo
    }.
