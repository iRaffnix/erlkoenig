#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 29: dns.allowlist capability wires from spawn opts to
%% erlkoenig_dns_filter automatically (SPEC-AS-009 Phase B).
%%
%% Phase A (test 28) verified the runtime enforcement — a registered
%% allowlist answers denied names with NXDOMAIN. This test verifies
%% the lifecycle wiring:
%%
%%   1. A container spawned with `dns_allowlist => [<<"...">>]` ends
%%      up with its IP + compiled patterns in the filter's ETS as
%%      soon as it reaches `running`.
%%   2. Stopping the container drops the registration — a recycled
%%      IP does not inherit the previous tenant's policy.
%%
%% The opts key mirrors exactly what the DSL emits from
%% `requires :"dns.allowlist", hosts: [...]`.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 29: dns.allowlist DSL auto-register ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    test_helper:boot(),
    logger:set_primary_config(level, error),

    Ip = {10, 0, 0, 91},
    Hosts = [<<"allowed.example">>, <<"*.wild.example">>],

    %% Precondition: filter empty for this IP
    no_filter = erlkoenig_dns_filter:check(Ip, <<"allowed.example">>),

    Pid = test_helper:step(
      "spawn echo_server with dns_allowlist opt",
      fun() ->
          {ok, P} = erlkoenig:spawn(test_helper:demo("echo_server"),
              #{ip => Ip,
                args => [<<"7029">>],
                name => <<"dns_allow_test">>,
                dns_allowlist => Hosts}),
          ok = wait_running(P, 10_000),
          {ok, P}
      end),

    test_helper:step(
      "filter ETS has the container's IP + compiled patterns",
      fun() ->
          case ets:lookup(erlkoenig_dns_filter, Ip) of
              [{Ip, Patterns}] ->
                  case Patterns of
                      [{exact, <<"allowed.example">>},
                       {suffix, <<"wild.example">>}] -> ok;
                      Other -> {error, {wrong_patterns, Other}}
                  end;
              [] ->
                  {error, no_ets_entry}
          end
      end),

    test_helper:step(
      "direct check() returns deny for non-allowed name",
      fun() ->
          case erlkoenig_dns_filter:check(Ip, <<"evil.example">>) of
              {deny, not_in_allowlist} -> ok;
              Other -> {error, {unexpected, Other}}
          end
      end),

    test_helper:step(
      "direct check() returns allow for exact match",
      fun() ->
          case erlkoenig_dns_filter:check(Ip, <<"allowed.example">>) of
              allow -> ok;
              Other -> {error, {unexpected, Other}}
          end
      end),

    test_helper:step(
      "direct check() returns allow for wildcard match",
      fun() ->
          case erlkoenig_dns_filter:check(Ip, <<"foo.wild.example">>) of
              allow -> ok;
              Other -> {error, {unexpected, Other}}
          end
      end),

    test_helper:step(
      "stop container: filter ETS entry gone",
      fun() ->
          ok = erlkoenig:stop(Pid),
          %% unregister happens in stopped(enter); give the gen_statem
          %% a moment to process the transition + audit writes.
          wait_until_gone(Ip, 20)
      end),

    test_helper:step(
      "check() returns no_filter again after unregister",
      fun() ->
          no_filter = erlkoenig_dns_filter:check(Ip, <<"evil.example">>),
          ok
      end),

    io:format("~n=== Test 29 passed ===~n~n"),
    halt(0).

wait_running(Pid, TimeoutMs) ->
    wait_running(Pid, TimeoutMs, erlang:monotonic_time(millisecond)).
wait_running(Pid, TimeoutMs, Start) ->
    case erlkoenig:inspect(Pid) of
        #{state := running}       -> ok;
        #{state := failed,
          error := Why}           -> error({container_failed, Why});
        {error, not_found}        -> error({container_disappeared, Pid});
        _ ->
            case erlang:monotonic_time(millisecond) - Start >= TimeoutMs of
                true  -> error(timeout_waiting_for_running);
                false ->
                    timer:sleep(100),
                    wait_running(Pid, TimeoutMs, Start)
            end
    end.

wait_until_gone(_Ip, 0) ->
    {error, ets_entry_lingered};
wait_until_gone(Ip, N) ->
    case ets:lookup(erlkoenig_dns_filter, Ip) of
        [] -> ok;
        _  ->
            timer:sleep(100),
            wait_until_gone(Ip, N - 1)
    end.
