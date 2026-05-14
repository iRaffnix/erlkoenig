%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_ct_observe_tests).

-include_lib("eunit/include/eunit.hrl").

user_stop_sigkill_is_not_oom_test() ->
    ?assertNot(erlkoenig_ct_observe:should_notify_oom(
                 true, #{exit_code => 137, term_signal => 9}, false)).

user_stop_suppresses_stale_cgroup_oom_signal_test() ->
    ?assertNot(erlkoenig_ct_observe:should_notify_oom(
                 true, #{exit_code => 137, term_signal => 9}, true)).

non_user_sigkill_remains_oom_fallback_test() ->
    ?assert(erlkoenig_ct_observe:should_notify_oom(
              false, #{exit_code => 137, term_signal => 9}, false)).

cgroup_oom_is_authoritative_for_non_user_exit_test() ->
    ?assert(erlkoenig_ct_observe:should_notify_oom(
              false, #{exit_code => 1, term_signal => 0}, true)).

non_signal_exit_is_not_oom_test() ->
    ?assertNot(erlkoenig_ct_observe:should_notify_oom(
                 false, #{exit_code => 0, term_signal => 0}, false)).
