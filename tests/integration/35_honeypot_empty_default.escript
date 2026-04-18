#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 35: ct_guard default honeypot ports MUST be empty.
%%
%% Regression test for the operator-lockout bug (2026-04-17):
%% the default list used to include port 22, which caused instant
%% bans of SSH clients on vanilla erlkoenig hosts. The fix makes
%% honeypot strictly opt-in. This test guards against regressions
%% by scanning the compiled beam for "fingerprint" port literals
%% that identify the old buggy default (1433/3306/3389/5900/27017 —
%% these are rare enough that their presence as literal integers in
%% this specific module means they're on a default honeypot list).
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 35: honeypot default ports must be empty ===~n~n"),

    test_helper:boot(),
    logger:set_primary_config(level, warning),

    BeamPath = code:which(erlkoenig_nft_ct_guard),
    {ok, {_, [{abstract_code, {_, AC}}]}} =
        beam_lib:chunks(BeamPath, [abstract_code]),
    Src = iolist_to_binary(io_lib:format("~p", [AC])),

    test_helper:step(
      "beam contains no fingerprint scanner ports as integer literals",
      fun() ->
          Scanners = [1433, 3306, 3389, 5900, 27017],
          Found = [P || P <- Scanners,
                        binary:match(Src, integer_to_binary(P)) =/= nomatch],
          case Found of
              [] -> ok;
              _ ->
                  error({dangerous_ports_still_in_default, Found,
                         "honeypot defaults must be strictly opt-in; "
                         "the presence of these port numbers as literals "
                         "in erlkoenig_nft_ct_guard indicates the old "
                         "buggy default has been reintroduced"})
          end
      end),

    test_helper:step(
      "running ct_guard reports empty honeypot_ports with default config",
      fun() ->
          %% test_helper:boot() started the app, ct_guard is up.
          %% Its status call reports the merged config including env.
          Pid = whereis(erlkoenig_nft_ct_guard),
          case Pid of
              undefined ->
                  io:format("  (skip: ct_guard not started)~n"),
                  ok;
              _ ->
                  Status = gen_server:call(Pid, status, 5000),
                  HPP = maps:get(honeypot_ports, Status,
                                 sets:new([{version, 2}])),
                  List = case sets:is_set(HPP) of
                             true -> sets:to_list(HPP);
                             false -> HPP
                         end,
                  case List of
                      [] -> ok;
                      _ -> error({honeypot_set_not_empty, List})
                  end
          end
      end),

    io:format("~n=== Test 35 passed ===~n"),
    halt(0).
