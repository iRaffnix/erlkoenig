%%%-------------------------------------------------------------------
%%% @doc Unit tests for pre-spawn security gates.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_ct_security_tests).

-include_lib("eunit/include/eunit.hrl").

admission_missing_fails_open_in_development_test() ->
    application:set_env(erlkoenig, resource_protection, #{mode => development}),
    Hidden = hide_registered(erlkoenig_admission),
    try
        ?assertEqual({ok, undefined},
                     erlkoenig_ct_security:safe_admission_acquire(host))
    after
        restore_registered(erlkoenig_admission, Hidden),
        application:unset_env(erlkoenig, resource_protection)
    end.

admission_missing_fails_closed_in_production_test() ->
    application:set_env(erlkoenig, resource_protection, #{mode => production}),
    Hidden = hide_registered(erlkoenig_admission),
    try
        ?assertEqual({error, admission_unavailable},
                     erlkoenig_ct_security:safe_admission_acquire(host))
    after
        restore_registered(erlkoenig_admission, Hidden),
        application:unset_env(erlkoenig, resource_protection)
    end.

quarantine_missing_fails_open_in_development_test() ->
    application:set_env(erlkoenig, resource_protection, #{mode => development}),
    Hidden = hide_registered(erlkoenig_quarantine),
    try
        ?assertEqual(ok,
                     erlkoenig_ct_security:safe_quarantine_check(<<"/bin/sh">>))
    after
        restore_registered(erlkoenig_quarantine, Hidden),
        application:unset_env(erlkoenig, resource_protection)
    end.

quarantine_missing_fails_closed_in_production_test() ->
    application:set_env(erlkoenig, resource_protection, #{mode => production}),
    Hidden = hide_registered(erlkoenig_quarantine),
    try
        ?assertEqual({error, quarantine_unavailable},
                     erlkoenig_ct_security:safe_quarantine_check(<<"/bin/sh">>))
    after
        restore_registered(erlkoenig_quarantine, Hidden),
        application:unset_env(erlkoenig, resource_protection)
    end.

hide_registered(Name) ->
    case whereis(Name) of
        undefined ->
            undefined;
        Pid ->
            true = unregister(Name),
            Pid
    end.

restore_registered(_Name, undefined) ->
    ok;
restore_registered(Name, Pid) ->
    case is_process_alive(Pid) of
        false ->
            ok;
        true ->
            true = register(Name, Pid),
            ok
    end.
