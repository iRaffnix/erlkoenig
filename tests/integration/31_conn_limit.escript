#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 31: `conn_limit per_ip` — SPEC-EK-028 Tracker column #1.
%%
%% Verifies end-to-end:
%%
%%   DSL-equivalent nft term  →  per-container nft install
%%     →  `ct count over 2 saddr drop` rule live in kernel netns
%%       →  3rd concurrent connection from same source DROPPED
%%         →  closing one frees the slot
%%
%% Post-Glasbox-refactor: the container is spawned with an explicit
%% `nft` map in Opts (exactly what the DSL emits from an inline
%% `nft do input ... end end` block with a `conn_limit per_ip: 2`
%% rule). No more auto-synthesised chain — the rule lives where the
%% term says it does, and that's inspectable via `nft list ruleset`.
%%
%% Root required.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 31: conn_limit per_ip drops 3rd concurrent ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    test_helper:boot(),
    logger:set_primary_config(level, error),

    Ip = {10, 0, 0, 231},
    EchoPort = 7031,

    %% The `nft` map is exactly what the Stack DSL produces for:
    %%   container "ct", ... do
    %%     nft do
    %%       input policy: :accept do
    %%         conn_limit per_ip: 2
    %%       end
    %%     end
    %%   end
    NftMap = #{
        chains => [#{
            name => <<"input">>,
            hook => input,
            type => filter,
            priority => 0,
            policy => accept,
            rules => [{connlimit_drop, #{max => 2}}]
        }]
    },

    Pid = test_helper:step(
      "spawn echo with one conn_limit per_ip: 2 rule",
      fun() ->
          {ok, P} = erlkoenig:spawn(
              test_helper:demo("echo_server"),
              #{ip => Ip,
                args => [integer_to_binary(EchoPort)],
                name => <<"connlim_test">>,
                nft => NftMap}),
          ok = wait_running(P, 10_000),
          {ok, P}
      end),

    test_helper:step(
      "installed rule is visible in the container netns",
      fun() ->
          Info = erlkoenig:inspect(Pid),
          OsPid = maps:get(os_pid, Info),
          Out = os:cmd("nsenter --target " ++ integer_to_list(OsPid) ++
                       " --net nft list ruleset 2>&1"),
          %% Glasbox probe: the rule shows up in the input chain,
          %% not in some hidden synthetic chain — no surprises.
          case re:run(Out, "ct count over 2.*drop", [{capture, none}]) of
              match -> ok;
              _     -> {error, {rule_not_found, Out}}
          end
      end),

    test_helper:step(
      "first 2 concurrent connections succeed",
      fun() ->
          {ok, S1} = gen_tcp:connect(Ip, EchoPort,
              [binary, {active, false}], 2000),
          {ok, S2} = gen_tcp:connect(Ip, EchoPort,
              [binary, {active, false}], 2000),
          put(s1, S1), put(s2, S2),
          ok
      end),

    test_helper:step(
      "3rd concurrent connection is refused by kernel",
      fun() ->
          case gen_tcp:connect(Ip, EchoPort,
                 [binary, {active, false}], 1500) of
              {ok, S3} ->
                  gen_tcp:close(S3),
                  {error, third_connect_should_have_failed};
              {error, _} -> ok
          end
      end),

    test_helper:step(
      "closing one of the first two frees a slot",
      fun() ->
          gen_tcp:close(get(s1)),
          timer:sleep(500),
          case gen_tcp:connect(Ip, EchoPort,
                 [binary, {active, false}], 1500) of
              {ok, S4} ->
                  put(s4, S4),
                  ok;
              {error, Reason} ->
                  {error, {connect_after_free_failed, Reason}}
          end
      end),

    _ = gen_tcp:close(get(s2)),
    _ = gen_tcp:close(get(s4)),
    test_helper:cleanup([Pid]),
    io:format("~n=== Test 31 passed ===~n~n"),
    halt(0).

wait_running(Pid, TimeoutMs) ->
    wait_running(Pid, TimeoutMs, erlang:monotonic_time(millisecond)).
wait_running(Pid, TimeoutMs, Start) ->
    case erlkoenig:inspect(Pid) of
        #{state := running} -> ok;
        #{state := failed, error := Why} ->
            error({container_failed, Why});
        {error, not_found} ->
            error({container_disappeared, Pid});
        _ ->
            case erlang:monotonic_time(millisecond) - Start >= TimeoutMs of
                true  -> error(timeout_waiting_for_running);
                false ->
                    timer:sleep(100),
                    wait_running(Pid, TimeoutMs, Start)
            end
    end.
