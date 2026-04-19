#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 39: audit Ed25519 signing end-to-end (SPEC-AS-005 stage 2).
%%
%% Verifies that:
%%   - When `audit_signing_key` is configured, every event carries an
%%     Ed25519 signature (128 hex chars = 64 raw bytes).
%%   - signing_pubkey/0 exposes the public key for customer-side
%%     verification (the customer hands it to their auditor).
%%   - verify_chain/2 with the right pubkey returns {ok, N}.
%%   - verify_chain/2 with a wrong pubkey reports signature_invalid.
%%   - Tampering with a signed event is detected at the right line.
%%   - Restart of the gen_server reloads the same key and continues
%%     producing signatures verifiable by the same pubkey.
%%
%% Stage 2 is OPTIONAL — when no key is configured, signature is null
%% and the chain still verifies at the hash level (test 38).
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 39: audit Ed25519 signing ===~n~n"),

    test_helper:add_paths(),
    logger:set_primary_config(level, warning),

    %% Use OS time + unique_integer so the path differs across escript
    %% invocations (unique_integer alone is only per-VM-lifetime).
    Tag = integer_to_list(os:system_time(microsecond)) ++ "_" ++
          integer_to_list(erlang:unique_integer([positive])),
    Path = "/tmp/erlkoenig_audit_sig_test_" ++ Tag ++ "/audit.jsonl",
    KeyPath = "/tmp/erlkoenig_audit_sig_test_key_" ++ Tag ++ ".raw",

    %% Generate a fresh keypair, write the private key to disk
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    32 = byte_size(PrivKey),
    32 = byte_size(PubKey),
    ok = file:write_file(KeyPath, PrivKey),

    application:set_env(erlkoenig, audit_path, Path),
    application:set_env(erlkoenig, audit_signing_key, KeyPath),
    _ = (catch gen_server:stop(erlkoenig_audit)),
    {ok, _Pid1} = erlkoenig_audit:start_link(),

    test_helper:step(
      "signing_pubkey/0 returns the loaded key",
      fun() ->
          PubKey = erlkoenig_audit:signing_pubkey(),
          ok
      end),

    test_helper:step(
      "every event carries a 128-hex-char Ed25519 signature",
      fun() ->
          erlkoenig_audit:log(#{type => integration_sign_a,
                                subject => <<"alpha">>, result => ok}),
          erlkoenig_audit:log(#{type => integration_sign_b,
                                subject => <<"bravo">>, result => ok}),
          erlkoenig_audit:log(#{type => integration_sign_c,
                                subject => <<"charlie">>, result => ok}),
          flush_audit(),
          Events = read_events(Path),
          3 = length(Events),
          lists:foreach(fun(E) ->
              Sig = maps:get(<<"signature">>, E),
              true = is_binary(Sig),
              128 = byte_size(Sig)
          end, Events),
          ok
      end),

    test_helper:step(
      "verify_chain/2 with correct pubkey returns {ok, 3}",
      fun() ->
          {ok, 3} = erlkoenig_audit:verify_chain(Path, PubKey),
          ok
      end),

    test_helper:step(
      "verify_chain/1 (no key) checks hash chain only - also passes",
      fun() ->
          {ok, 3} = erlkoenig_audit:verify_chain(Path),
          ok
      end),

    test_helper:step(
      "verify_chain/2 with WRONG pubkey reports signature_invalid",
      fun() ->
          {WrongPub, _} = crypto:generate_key(eddsa, ed25519),
          case erlkoenig_audit:verify_chain(Path, WrongPub) of
              {error, {signature_invalid, 1, _}} -> ok;
              Other ->
                  error({expected_signature_invalid, Other})
          end
      end),

    test_helper:step(
      "tampering breaks verification at the correct line",
      fun() ->
          ok = gen_server:stop(erlkoenig_audit),
          {ok, Bin} = file:read_file(Path),
          %% Replace "alpha" → "ALPHA" in event 1
          Tampered = binary:replace(Bin,
              <<"\"subject\":\"alpha\"">>,
              <<"\"subject\":\"ALPHA\"">>),
          case Bin =:= Tampered of
              true -> error({no_replacement_happened, Bin});
              false -> ok
          end,
          ok = file:write_file(Path, Tampered),
          %% Either the hash check fires first OR the signature check —
          %% both prove the tamper is detected. Both report line 1.
          case erlkoenig_audit:verify_chain(Path, PubKey) of
              {error, {chain_break, 1, _}}        -> ok;
              {error, {signature_invalid, 1, _}}  -> ok;
              Other ->
                  error({expected_failure_at_line_1, Other})
          end
      end),

    test_helper:step(
      "key reloads after gen_server restart",
      fun() ->
          %% Start a fresh log file for this step
          Path2 = "/tmp/erlkoenig_audit_sig_restart_" ++
                  integer_to_list(erlang:unique_integer([positive])) ++
                  "/audit.jsonl",
          application:set_env(erlkoenig, audit_path, Path2),
          {ok, _Pid2} = erlkoenig_audit:start_link(),
          PubKey = erlkoenig_audit:signing_pubkey(),
          erlkoenig_audit:log(#{type => after_restart,
                                subject => <<"fresh">>, result => ok}),
          flush_audit(),
          {ok, 1} = erlkoenig_audit:verify_chain(Path2, PubKey),
          gen_server:stop(erlkoenig_audit),
          file:delete(Path2),
          file:del_dir(filename:dirname(Path2)),
          ok
      end),

    %% Cleanup
    _ = file:delete(Path),
    _ = file:delete(KeyPath),
    _ = file:del_dir(filename:dirname(Path)),
    application:unset_env(erlkoenig, audit_path),
    application:unset_env(erlkoenig, audit_signing_key),

    io:format("~n=== Test 39 passed ===~n"),
    halt(0).

flush_audit() ->
    _ = erlkoenig_audit:query(#{limit => 0}),
    timer:sleep(30).

read_events(Path) ->
    {ok, Bin} = file:read_file(Path),
    Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]), L =/= <<>>],
    [json:decode(L) || L <- Lines].
