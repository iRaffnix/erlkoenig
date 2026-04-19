#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 43: strict-mode capability enforcement for `:dns.local`.
%%
%% Proves the runtime enforcement layer that turns the DSL
%% `requires :"dns.local"` declaration from documentation into
%% policy.
%%
%% Two containers, both spawned with strict_capabilities=true:
%%   1. WITH `requires :"dns.local"` in extra_opts → /etc/resolv.conf
%%      points at the zone gateway; getaddrinfo() works.
%%   2. WITHOUT the declaration → /etc/resolv.conf is empty
%%      (the C runtime skips the write when dns_ip=0). Workload
%%      cannot resolve names; the operator forgot to declare the
%%      dependency, and the test catches it.
%%
%% Needs root.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 43: strict-mode :dns.local ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    application:set_env(erlkoenig, strict_capabilities, true),
    test_helper:boot(),
    logger:set_primary_config(level, error),

    Tag = integer_to_list(os:system_time(microsecond)),
    NameOk   = list_to_binary("t43-ok-" ++ Tag),
    NameNoDns = list_to_binary("t43-nodns-" ++ Tag),

    PidOk = test_helper:step(
      "container WITH requires :dns.local -resolv.conf populated",
      fun() ->
          {ok, P} = erlkoenig:spawn(test_helper:demo("echo_server"),
              #{ip => {10, 0, 0, 245},
                args => [<<"7777">>],
                name => NameOk,
                requires => ['dns.local']}),
          ok = wait_for_running(P, 15000),
          {ok, P}
      end),

    test_helper:step(
      "  /etc/resolv.conf inside container has a nameserver line",
      fun() ->
          OsPid = maps:get(os_pid, erlkoenig:inspect(PidOk)),
          ResolvPath = lists:flatten(
              io_lib:format("/proc/~p/root/etc/resolv.conf", [OsPid])),
          {ok, Bin} = file:read_file(ResolvPath),
          case binary:match(Bin, <<"nameserver ">>) of
              nomatch -> error({no_nameserver_in_resolv_conf, Bin});
              _       ->
                  io:format("    resolv.conf: ~s~n",
                            [string:trim(binary_to_list(Bin))]),
                  ok
          end
      end),

    PidNoDns = test_helper:step(
      "container WITHOUT requires -resolv.conf empty (strict mode)",
      fun() ->
          {ok, P} = erlkoenig:spawn(test_helper:demo("echo_server"),
              #{ip => {10, 0, 0, 246},
                args => [<<"7777">>],
                name => NameNoDns}),
          ok = wait_for_running(P, 15000),
          {ok, P}
      end),

    test_helper:step(
      "  /etc/resolv.conf inside that container is empty/missing",
      fun() ->
          OsPid = maps:get(os_pid, erlkoenig:inspect(PidNoDns)),
          ResolvPath = lists:flatten(
              io_lib:format("/proc/~p/root/etc/resolv.conf", [OsPid])),
          case file:read_file(ResolvPath) of
              {error, enoent} ->
                  io:format("    no /etc/resolv.conf -strict opt-out works~n"),
                  ok;
              {ok, <<>>} ->
                  io:format("    /etc/resolv.conf is empty -strict opt-out works~n"),
                  ok;
              {ok, Bin} ->
                  case binary:match(Bin, <<"nameserver ">>) of
                      nomatch ->
                          io:format("    resolv.conf has no nameserver "
                                    "(content: ~p)~n", [Bin]),
                          ok;
                      _ ->
                          error({nameserver_present_despite_no_requires, Bin})
                  end
          end
      end),

    %% Cleanup.
    catch erlkoenig:stop(PidOk),
    catch erlkoenig:stop(PidNoDns),
    application:unset_env(erlkoenig, strict_capabilities),

    io:format("~n=== Test 43 passed ===~n"),
    halt(0).

wait_for_running(P, TimeoutMs) ->
    wait_for_running(P, TimeoutMs, erlang:monotonic_time(millisecond)).
wait_for_running(P, TimeoutMs, Start) ->
    case erlkoenig:inspect(P) of
        #{state := running} -> ok;
        #{state := failed, error := Why} -> error({container_failed, Why});
        {error, not_found} -> error({container_disappeared, P});
        _ ->
            case erlang:monotonic_time(millisecond) - Start >= TimeoutMs of
                true  -> error(timeout_waiting_for_running);
                false ->
                    timer:sleep(100),
                    wait_for_running(P, TimeoutMs, Start)
            end
    end.
