%%%-------------------------------------------------------------------
%%% @doc EUnit tests for erlkoenig_dns_filter.
%%%
%%% Covers pattern compilation, exact + wildcard match semantics,
%%% case/trailing-dot normalisation, registration lifecycle, and
%%% the fail-open behaviour when the table is missing.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_dns_filter_tests).

-include_lib("eunit/include/eunit.hrl").

%% =================================================================
%% Pattern compilation
%% =================================================================

compile_exact_test() ->
    [{exact, <<"api.openai.com">>}] =
        erlkoenig_dns_filter:compile_patterns([<<"api.openai.com">>]).

compile_wildcard_test() ->
    [{suffix, <<"github.com">>}] =
        erlkoenig_dns_filter:compile_patterns([<<"*.github.com">>]).

compile_mixed_test() ->
    [{exact, <<"api.openai.com">>},
     {suffix, <<"s3.amazonaws.com">>},
     {exact, <<"example.com">>}] =
        erlkoenig_dns_filter:compile_patterns(
          [<<"api.openai.com">>,
           <<"*.s3.amazonaws.com">>,
           <<"example.com">>]).

compile_lowercases_test() ->
    [{exact, <<"api.openai.com">>}] =
        erlkoenig_dns_filter:compile_patterns([<<"API.OpenAI.COM">>]).

compile_strips_trailing_dot_test() ->
    [{exact, <<"api.openai.com">>}] =
        erlkoenig_dns_filter:compile_patterns([<<"api.openai.com.">>]).

%% =================================================================
%% compile_one — rejection of malformed wildcards (Muster 9)
%% =================================================================
%%
%% Regression guard: `"*."`, `"*"`, `"**.foo"`, `"*abc"` all used to
%% fall through to the generic exact-match clause (the first-clause
%% guard `byte_size(Rest) > 0` failed, the next clause took anything
%% non-empty), producing silently-dead patterns like `{exact, <<"*">>}`
%% that can't match any real DNS query. Operators writing a typo in
%% the wildcard got no feedback and an allowlist entry that did
%% nothing. DSL rejects these via regex; the module-level parser now
%% follows suit.

compile_rejects_lone_star_test() ->
    ?assertEqual([{error, invalid_host}],
                 erlkoenig_dns_filter:compile_patterns([<<"*">>])).

compile_rejects_star_dot_test() ->
    ?assertEqual([{error, invalid_host}],
                 erlkoenig_dns_filter:compile_patterns([<<"*.">>])).

compile_rejects_double_star_wildcard_test() ->
    ?assertEqual([{error, invalid_host}],
                 erlkoenig_dns_filter:compile_patterns([<<"**.foo">>])).

compile_rejects_star_prefix_no_dot_test() ->
    %% "*abc" is neither "*.<rest>" nor a valid literal hostname.
    ?assertEqual([{error, invalid_host}],
                 erlkoenig_dns_filter:compile_patterns([<<"*abc">>])).

compile_rejects_empty_binary_test() ->
    ?assertEqual([{error, invalid_host}],
                 erlkoenig_dns_filter:compile_patterns([<<>>])).

compile_accepts_valid_wildcard_after_star_rejection_test() ->
    %% Sanity: the valid `*.rest` shape still compiles correctly
    %% now that the stricter clause exists.
    ?assertEqual([{suffix, <<"example.com">>}],
                 erlkoenig_dns_filter:compile_patterns(
                     [<<"*.example.com">>])).

%% =================================================================
%% Lifecycle (start / register / check / unregister)
%% =================================================================

filter_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      fun no_filter_for_unregistered_ip/0,
      fun exact_match_allow/0,
      fun exact_match_deny_other/0,
      fun exact_match_case_insensitive/0,
      fun exact_match_strips_trailing_dot/0,
      fun wildcard_one_label/0,
      fun wildcard_multiple_labels/0,
      fun wildcard_does_not_match_bare/0,
      fun wildcard_does_not_match_neighbouring_domain/0,
      fun mixed_allowlist/0,
      fun re_register_replaces_allowlist/0,
      fun unregister_returns_no_filter/0,
      fun unregister_idempotent/0
     ]}.

setup() ->
    {ok, Pid} = erlkoenig_dns_filter:start_link(),
    Pid.

cleanup(_Pid) ->
    catch erlkoenig_dns_filter:stop(),
    ok.

no_filter_for_unregistered_ip() ->
    no_filter = erlkoenig_dns_filter:check({10, 0, 0, 99},
                                            <<"anywhere.com">>).

exact_match_allow() ->
    ok = erlkoenig_dns_filter:register_allowlist(
           {10, 0, 0, 1}, [<<"api.openai.com">>]),
    allow = erlkoenig_dns_filter:check({10, 0, 0, 1},
                                        <<"api.openai.com">>).

exact_match_deny_other() ->
    ok = erlkoenig_dns_filter:register_allowlist(
           {10, 0, 0, 2}, [<<"api.openai.com">>]),
    {deny, not_in_allowlist} =
        erlkoenig_dns_filter:check({10, 0, 0, 2}, <<"evil.com">>).

exact_match_case_insensitive() ->
    ok = erlkoenig_dns_filter:register_allowlist(
           {10, 0, 0, 3}, [<<"api.openai.com">>]),
    allow = erlkoenig_dns_filter:check({10, 0, 0, 3},
                                        <<"API.OpenAI.COM">>).

exact_match_strips_trailing_dot() ->
    ok = erlkoenig_dns_filter:register_allowlist(
           {10, 0, 0, 4}, [<<"api.openai.com">>]),
    allow = erlkoenig_dns_filter:check({10, 0, 0, 4},
                                        <<"api.openai.com.">>).

wildcard_one_label() ->
    ok = erlkoenig_dns_filter:register_allowlist(
           {10, 0, 0, 5}, [<<"*.github.com">>]),
    allow = erlkoenig_dns_filter:check({10, 0, 0, 5},
                                        <<"raw.github.com">>).

wildcard_multiple_labels() ->
    ok = erlkoenig_dns_filter:register_allowlist(
           {10, 0, 0, 6}, [<<"*.s3.amazonaws.com">>]),
    allow = erlkoenig_dns_filter:check({10, 0, 0, 6},
                                        <<"my-bucket.eu-west-1.s3.amazonaws.com">>).

wildcard_does_not_match_bare() ->
    %% `*.github.com` must NOT match the bare `github.com`.
    ok = erlkoenig_dns_filter:register_allowlist(
           {10, 0, 0, 7}, [<<"*.github.com">>]),
    {deny, not_in_allowlist} =
        erlkoenig_dns_filter:check({10, 0, 0, 7}, <<"github.com">>).

wildcard_does_not_match_neighbouring_domain() ->
    %% `*.github.com` must NOT match `evilgithub.com` (no leading dot).
    ok = erlkoenig_dns_filter:register_allowlist(
           {10, 0, 0, 8}, [<<"*.github.com">>]),
    {deny, not_in_allowlist} =
        erlkoenig_dns_filter:check({10, 0, 0, 8}, <<"evilgithub.com">>).

mixed_allowlist() ->
    ok = erlkoenig_dns_filter:register_allowlist(
           {10, 0, 0, 9},
           [<<"api.openai.com">>,
            <<"*.s3.amazonaws.com">>,
            <<"github.com">>]),
    allow = erlkoenig_dns_filter:check({10, 0, 0, 9},
                                        <<"api.openai.com">>),
    allow = erlkoenig_dns_filter:check({10, 0, 0, 9},
                                        <<"github.com">>),
    allow = erlkoenig_dns_filter:check({10, 0, 0, 9},
                                        <<"foo.s3.amazonaws.com">>),
    {deny, not_in_allowlist} =
        erlkoenig_dns_filter:check({10, 0, 0, 9}, <<"evil.com">>).

re_register_replaces_allowlist() ->
    Ip = {10, 0, 0, 10},
    ok = erlkoenig_dns_filter:register_allowlist(Ip, [<<"a.com">>]),
    allow = erlkoenig_dns_filter:check(Ip, <<"a.com">>),
    %% re-register with a different list — old entries gone
    ok = erlkoenig_dns_filter:register_allowlist(Ip, [<<"b.com">>]),
    {deny, not_in_allowlist} =
        erlkoenig_dns_filter:check(Ip, <<"a.com">>),
    allow = erlkoenig_dns_filter:check(Ip, <<"b.com">>).

unregister_returns_no_filter() ->
    Ip = {10, 0, 0, 11},
    ok = erlkoenig_dns_filter:register_allowlist(Ip, [<<"a.com">>]),
    allow = erlkoenig_dns_filter:check(Ip, <<"a.com">>),
    ok = erlkoenig_dns_filter:unregister(Ip),
    no_filter = erlkoenig_dns_filter:check(Ip, <<"a.com">>).

unregister_idempotent() ->
    ok = erlkoenig_dns_filter:unregister({10, 0, 0, 12}),
    ok = erlkoenig_dns_filter:unregister({10, 0, 0, 12}).

%% =================================================================
%% Fail-open: missing table behaves as no_filter
%% =================================================================

fail_open_when_table_missing_test() ->
    %% Filter not started → no ETS table → check should not crash,
    %% must return no_filter so DNS keeps working.
    catch erlkoenig_dns_filter:stop(),
    no_filter = erlkoenig_dns_filter:check({10, 0, 0, 1},
                                            <<"anywhere.com">>).
