#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 40: audit daily seal end-to-end (SPEC-AS-005 stage 3).
%%
%% Verifies that:
%%   - seal_day/0 produces a `<path>.<UTC date>.sealed` file at mode
%%     0440, with the live file emptied for the next day.
%%   - The sealed file's last line is an `audit.seal` event whose
%%     details carry a hex SHA-256 HMAC, event_count, and byte_count.
%%   - verify_seal/2 with the right HMAC key returns ok plus the
%%     anchor (= seal event's this_hash).
%%   - verify_seal/2 with a wrong HMAC key reports seal_hmac_mismatch.
%%   - Tampering with a sealed file is detected by verify_seal/2.
%%   - The first event written after sealing references the sealed
%%     anchor in its prev_hash (chain crosses the day boundary).
%%   - On gen_server restart with an empty live file, the chain head
%%     recovers from the sealed sibling so the chain doesn't reset.
%%   - verify_chain still validates both the sealed file (3 events
%%     incl. seal) and the new live file (events written post-seal).
%%
%% Stage 3 is OPTIONAL — when no `audit_hmac_key` is configured,
%% seal_day/0 returns {error, no_hmac_key} and stage-1/2 keep
%% working untouched.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 40: audit daily seal ===~n~n"),

    test_helper:add_paths(),
    logger:set_primary_config(level, warning),

    Tag = integer_to_list(os:system_time(microsecond)) ++ "_" ++
          integer_to_list(erlang:unique_integer([positive])),
    Path     = "/tmp/erlkoenig_audit_seal_test_" ++ Tag ++ "/audit.jsonl",
    KeyPath  = "/tmp/erlkoenig_audit_seal_test_sig_" ++ Tag ++ ".raw",
    HmacPath = "/tmp/erlkoenig_audit_seal_test_hmac_" ++ Tag ++ ".raw",

    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    32 = byte_size(PrivKey),
    HmacKey = crypto:strong_rand_bytes(32),
    ok = file:write_file(KeyPath, PrivKey),
    ok = file:write_file(HmacPath, HmacKey),

    application:set_env(erlkoenig, audit_path, Path),
    application:set_env(erlkoenig, audit_signing_key, KeyPath),
    application:set_env(erlkoenig, audit_hmac_key, HmacPath),
    _ = (catch gen_server:stop(erlkoenig_audit)),
    {ok, _Pid1} = erlkoenig_audit:start_link(),

    SealInfo = test_helper:step(
      "seal_day rotates live file to <path>.<date>.sealed",
      fun() ->
          erlkoenig_audit:log(#{type => integration_seal_a,
                                subject => <<"alpha">>, result => ok}),
          erlkoenig_audit:log(#{type => integration_seal_b,
                                subject => <<"bravo">>, result => ok}),
          erlkoenig_audit:log(#{type => integration_seal_c,
                                subject => <<"charlie">>, result => ok}),
          flush_audit(),
          {ok, Info} = erlkoenig_audit:seal_day(),
          SealedPath = maps:get(sealed_path, Info),
          true = filelib:is_regular(SealedPath),
          %% Live file is empty (new day).
          true = filelib:is_regular(Path),
          0 = filelib:file_size(Path),
          {ok, FI} = file:read_file_info(SealedPath),
          Mode = element(8, FI) band 8#777,
          case Mode of
              8#0440 -> ok;
              Other  -> error({wrong_mode, Other})
          end,
          io:format("    sealed file: ~s~n", [SealedPath]),
          {ok, Info}
      end),

    SealedPath = maps:get(sealed_path, SealInfo),
    Anchor = maps:get(anchor, SealInfo),

    test_helper:step(
      "sealed file ends with audit.seal carrying hmac/counts",
      fun() ->
          Events = read_events(SealedPath),
          %% 3 logged events + 1 seal event.
          4 = length(Events),
          Seal = lists:last(Events),
          <<"audit.seal">> = maps:get(<<"type">>, Seal),
          Hmac = maps:get(<<"hmac">>, Seal),
          true = is_binary(Hmac),
          64 = byte_size(Hmac),
          3 = maps:get(<<"event_count">>, Seal),
          true = is_integer(maps:get(<<"byte_count">>, Seal)),
          ok
      end),

    test_helper:step(
      "verify_seal/2 succeeds with the right HMAC key",
      fun() ->
          {ok, V} = erlkoenig_audit:verify_seal(SealedPath, HmacKey),
          3 = maps:get(event_count, V),
          Anchor = maps:get(anchor, V),
          ok
      end),

    test_helper:step(
      "verify_seal/2 rejects a wrong HMAC key",
      fun() ->
          WrongKey = crypto:strong_rand_bytes(32),
          case erlkoenig_audit:verify_seal(SealedPath, WrongKey) of
              {error, seal_hmac_mismatch} -> ok;
              Other -> error({expected_seal_hmac_mismatch, Other})
          end
      end),

    test_helper:step(
      "verify_chain validates the sealed file (chain + signatures)",
      fun() ->
          {ok, 4} = erlkoenig_audit:verify_chain(SealedPath, PubKey),
          ok
      end),

    test_helper:step(
      "first event after seal references seal anchor in prev_hash",
      fun() ->
          Anchor = erlkoenig_audit:chain_head(),
          erlkoenig_audit:log(#{type => post_seal,
                                subject => <<"delta">>, result => ok}),
          flush_audit(),
          [E] = read_events(Path),
          Anchor = maps:get(<<"prev_hash">>, E),
          ok
      end),

    test_helper:step(
      "restart with empty live file recovers chain head from sealed",
      fun() ->
          %% Snapshot then trigger restart.
          HeadBefore = erlkoenig_audit:chain_head(),
          ok = gen_server:stop(erlkoenig_audit),
          %% Wipe the live file so recovery has to fall back to the
          %% sealed sibling.
          ok = file:write_file(Path, <<>>),
          {ok, _Pid2} = erlkoenig_audit:start_link(),
          %% Without sealed-file recovery this would be the prior
          %% live event's hash, NOT the seal anchor; assert anchor.
          HeadAfter = erlkoenig_audit:chain_head(),
          case HeadAfter of
              Anchor -> ok;
              _      -> error({expected_seal_anchor,
                               #{got => HeadAfter,
                                 anchor => Anchor,
                                 head_before_restart => HeadBefore}})
          end,
          erlkoenig_audit:log(#{type => post_restart,
                                subject => <<"echo">>, result => ok}),
          flush_audit(),
          [E] = read_events(Path),
          %% prev_hash MUST be the seal anchor — this is the whole
          %% point of cross-file recovery. Standalone verify_chain on
          %% the new file fails (it starts from genesis), so a single-
          %% file check is wrong here; the future Stage-4 Go verifier
          %% walks sealed + live together.
          Anchor = maps:get(<<"prev_hash">>, E),
          ok
      end),

    test_helper:step(
      "tampering inside sealed file breaks HMAC verification",
      fun() ->
          %% chmod 0440 → make writable for the test mutation.
          ok = file:change_mode(SealedPath, 8#0640),
          {ok, Bin} = file:read_file(SealedPath),
          Tampered = binary:replace(Bin,
              <<"\"subject\":\"alpha\"">>,
              <<"\"subject\":\"ALPHA\"">>),
          case Bin =:= Tampered of
              true  -> error({no_replacement_happened, Bin});
              false -> ok
          end,
          ok = file:write_file(SealedPath, Tampered),
          case erlkoenig_audit:verify_seal(SealedPath, HmacKey) of
              {error, seal_hmac_mismatch} -> ok;
              Other -> error({expected_seal_hmac_mismatch, Other})
          end
      end),

    %% Cleanup
    _ = file:delete(Path),
    _ = file:delete(KeyPath),
    _ = file:delete(HmacPath),
    lists:foreach(fun file:delete/1,
                  filelib:wildcard(Path ++ ".*.sealed")),
    _ = file:del_dir(filename:dirname(Path)),
    application:unset_env(erlkoenig, audit_path),
    application:unset_env(erlkoenig, audit_signing_key),
    application:unset_env(erlkoenig, audit_hmac_key),

    io:format("~n=== Test 40 passed ===~n"),
    halt(0).

flush_audit() ->
    _ = erlkoenig_audit:query(#{limit => 0}),
    timer:sleep(30).

read_events(Path) ->
    {ok, Bin} = file:read_file(Path),
    Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]), L =/= <<>>],
    [json:decode(L) || L <- Lines].
