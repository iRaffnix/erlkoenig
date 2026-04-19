#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 38: audit hash chain end-to-end.
%%
%% Verifies SPEC-AS-005 stage-1 (hash chain without signing):
%%   - Every event carries prev_hash + this_hash + schema v=1.
%%   - Chain is linear: prev_hash[N] == this_hash[N-1].
%%   - Genesis event has 64-zero prev_hash.
%%   - verify_chain/1 returns {ok, N} on a clean log.
%%   - verify_chain/1 detects byte-level tampering at the right line.
%%   - BEAM restart reattaches to the existing chain head (no break).
%%
%% This is an integration test because it exercises the real gen_server
%% lifecycle (start, write, stop, restart) against a real filesystem,
%% not an isolated EUnit harness.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 38: audit hash chain ===~n~n"),

    %% This test does NOT need root. The hash chain is a pure
    %% userspace concern (file I/O + crypto:hash). We pull in just
    %% the erlkoenig ebin so erlkoenig_audit is loadable, then run
    %% the gen_server directly. No application:start required.
    test_helper:add_paths(),
    logger:set_primary_config(level, warning),

    %% OS time + unique_integer so the path differs across escript runs
    Tag = integer_to_list(os:system_time(microsecond)) ++ "_" ++
          integer_to_list(erlang:unique_integer([positive])),
    Path = "/tmp/erlkoenig_audit_test_38_" ++ Tag ++ "/audit.jsonl",

    application:set_env(erlkoenig, audit_path, Path),
    _ = (catch gen_server:stop(erlkoenig_audit)),
    {ok, _Pid1} = erlkoenig_audit:start_link(),

    test_helper:step(
      "three events produce linked chain with genesis prev_hash",
      fun() ->
          erlkoenig_audit:log(#{type => integration_test_a,
                                subject => <<"subject_a">>,
                                result => ok}),
          erlkoenig_audit:log(#{type => integration_test_b,
                                subject => <<"subject_b">>,
                                result => ok}),
          erlkoenig_audit:log(#{type => integration_test_c,
                                subject => <<"subject_c">>,
                                result => ok}),
          flush_audit(),
          Events = read_events(Path),
          3 = length(Events),
          [E1, E2, E3] = Events,
          Zero = <<"0000000000000000000000000000000000000000000000000000000000000000">>,
          Zero = maps:get(<<"prev_hash">>, E1),
          H1 = maps:get(<<"this_hash">>, E1),
          H2 = maps:get(<<"this_hash">>, E2),
          H1 = maps:get(<<"prev_hash">>, E2),
          H2 = maps:get(<<"prev_hash">>, E3),
          1 = maps:get(<<"v">>, E1),
          1 = maps:get(<<"v">>, E2),
          1 = maps:get(<<"v">>, E3),
          ok
      end),

    test_helper:step(
      "verify_chain returns {ok, 3} on the clean log",
      fun() ->
          {ok, 3} = erlkoenig_audit:verify_chain(Path),
          ok
      end),

    test_helper:step(
      "chain_head matches last event's this_hash",
      fun() ->
          Head = erlkoenig_audit:chain_head(),
          [_, _, E3] = read_events(Path),
          LastHash = maps:get(<<"this_hash">>, E3),
          Head = LastHash,  %% match: same value on both sides
          ok
      end),

    %% Restart the audit gen_server; the new instance must recover the
    %% chain head from disk and continue without a break.
    test_helper:step(
      "chain survives gen_server restart",
      fun() ->
          HeadBefore = erlkoenig_audit:chain_head(),
          ok = gen_server:stop(erlkoenig_audit),
          {ok, _Pid2} = erlkoenig_audit:start_link(),
          HeadAfter = erlkoenig_audit:chain_head(),
          HeadBefore = HeadAfter,
          erlkoenig_audit:log(#{type => integration_test_d,
                                subject => <<"subject_d">>,
                                result => ok}),
          flush_audit(),
          {ok, 4} = erlkoenig_audit:verify_chain(Path),
          ok
      end),

    test_helper:step(
      "tampering with a middle event breaks the chain at that line",
      fun() ->
          {ok, Before} = file:read_file(Path),
          %% Replace "subject_b" → "subject_B" in event 2.
          %% This must invalidate event 2's this_hash AND break event 3's
          %% prev_hash linkage. verify_chain reports the first mismatch.
          Tampered = binary:replace(Before,
              <<"\"subject\":\"subject_b\"">>,
              <<"\"subject\":\"subject_B\"">>),
          case Before =:= Tampered of
              true -> error({no_replacement_happened, Before});
              false -> ok
          end,
          %% Stop the writer so its buffered state doesn't race us.
          ok = gen_server:stop(erlkoenig_audit),
          ok = file:write_file(Path, Tampered),
          case erlkoenig_audit:verify_chain(Path) of
              {error, {chain_break, 2, Reason}} ->
                  io:format("    detected at line 2: ~p~n", [Reason]),
                  ok;
              Other ->
                  error({expected_chain_break_at_line_2, Other})
          end
      end),

    %% Cleanup.
    _ = file:delete(Path),
    _ = file:del_dir(filename:dirname(Path)),
    application:unset_env(erlkoenig, audit_path),

    io:format("~n=== Test 38 passed ===~n"),
    halt(0).

flush_audit() ->
    %% Force any pending writes to land by issuing a synchronous call.
    %% The gen_server runs cast-based logs but any call flushes ordering.
    _ = erlkoenig_audit:query(#{limit => 0}),
    timer:sleep(30).

read_events(Path) ->
    {ok, Bin} = file:read_file(Path),
    Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]), L =/= <<>>],
    [json:decode(L) || L <- Lines].
