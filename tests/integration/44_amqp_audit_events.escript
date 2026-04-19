#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 44: live AMQP emission of audit + capability events.
%%
%% Boots erlkoenig with AMQP pointed at the dev RabbitMQ broker,
%% then triggers the three new event types on the bus:
%%
%%   1. {audit_sealed, ...}        — daily seal completed
%%   2. {audit_chain_break, ...}   — verify_chain found tampering
%%   3. {capability_unmet, ...}    — strict-mode opt-out (no requires)
%%
%% Run a parallel `event_consumer.py audit.# capability.#` to watch
%% the messages land in real time.
%%
%% Needs the OTP app booted (test_helper:boot/0) so the AMQP
%% publisher subtree comes up. AMQP host/creds via env (with the
%% project's dev defaults).
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 44: live AMQP audit + capability events ===~n~n"),

    %% AMQP broker config must come from the environment — no
    %% hardcoded defaults (secrets + IPs belong outside git).
    AmqpHost = case os:getenv("AMQP_HOST") of
        false ->
            io:format(standard_error,
                      "error: set AMQP_HOST (e.g. AMQP_HOST=amqp.example "
                      "AMQP_USER=... AMQP_PASS=... ./44_amqp_audit_events.escript)~n",
                      []),
            halt(2);
        H -> H
    end,
    AmqpUser = list_to_binary(case os:getenv("AMQP_USER") of
        false ->
            io:format(standard_error, "error: set AMQP_USER~n", []), halt(2);
        U -> U
    end),
    AmqpPass = list_to_binary(case os:getenv("AMQP_PASS") of
        false ->
            io:format(standard_error, "error: set AMQP_PASS~n", []), halt(2);
        Pw -> Pw
    end),

    Tag = integer_to_list(os:system_time(microsecond)),
    AuditPath = "/tmp/erlkoenig_audit_test_44_" ++ Tag ++ ".jsonl",
    SignKey   = "/tmp/erlkoenig_sign_44_" ++ Tag ++ ".key",
    HmacKey   = "/tmp/erlkoenig_hmac_44_" ++ Tag ++ ".key",

    {_Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    file:write_file(SignKey, Priv),
    file:write_file(HmacKey, crypto:strong_rand_bytes(32)),
    application:set_env(erlkoenig, audit_path, AuditPath),
    application:set_env(erlkoenig, audit_signing_key, SignKey),
    application:set_env(erlkoenig, audit_hmac_key, HmacKey),

    test_helper:boot(),
    %% sys.config has amqp.enabled=false; override AFTER boot then
    %% start the publisher subtree manually so we hit the dev broker
    %% without editing sys.config on disk.
    AmqpCfg = #{
        enabled  => true,
        host     => AmqpHost,
        port     => 5672,
        user     => AmqpUser,
        password => AmqpPass
    },
    application:set_env(erlkoenig, amqp, AmqpCfg),
    case erlkoenig_amqp_sup:start_link(AmqpCfg) of
        {ok, _}                       -> ok;
        {error, {already_started, _}} -> ok
    end,
    %% Quiet logger but keep info from the publisher itself.
    logger:set_primary_config(level, warning),
    timer:sleep(1500), %% let the AMQP publisher connect

    io:format("    AMQP broker: ~s~n", [AmqpHost]),
    io:format("    listen with: AMQP_HOST=~s python3 tools/event_consumer.py "
              "~s 'audit.# capability.#'~n~n", [AmqpHost, AmqpHost]),

    test_helper:step(
      "trigger audit_sealed (write 2 events, then seal)",
      fun() ->
          erlkoenig_audit:log(#{type => morning, subject => <<"task1">>, result => ok}),
          erlkoenig_audit:log(#{type => morning, subject => <<"task2">>, result => ok}),
          timer:sleep(100),
          {ok, Info} = erlkoenig_audit:seal_day(),
          io:format("    sealed: ~s~n", [maps:get(sealed_path, Info)]),
          ok
      end),

    test_helper:step(
      "trigger audit_chain_break (tamper sealed file, run verify_chain)",
      fun() ->
          %% Find the sealed file, tamper, verify.
          [Sealed | _] = filelib:wildcard(AuditPath ++ ".*.sealed"),
          ok = file:change_mode(Sealed, 8#0640),
          {ok, Bin} = file:read_file(Sealed),
          Tampered = binary:replace(Bin, <<"task1">>, <<"TASK1">>),
          ok = file:write_file(Sealed, Tampered),
          {error, _} = erlkoenig_audit:verify_chain(Sealed),
          io:format("    chain_break event published~n"),
          ok
      end),

    test_helper:step(
      "trigger capability_unmet (strict mode + container without requires)",
      fun() ->
          application:set_env(erlkoenig, strict_capabilities, true),
          %% Clean stale rt processes from prior test runs.
          os:cmd("pkill -9 -f erlkoenig_rt 2>/dev/null"),
          timer:sleep(500),
          {ok, P} = erlkoenig:spawn(test_helper:demo("echo_server"),
              #{ip => {10, 0, 0, 244},
                args => [<<"7777">>],
                name => list_to_binary("t44-" ++ Tag)}),
          %% wait for spawn so effective_dns_ip ran
          timer:sleep(2000),
          catch erlkoenig:stop(P),
          application:unset_env(erlkoenig, strict_capabilities),
          io:format("    capability_unmet event published~n"),
          ok
      end),

    io:format("~n=== Test 44 done — check the consumer ===~n"),
    %% Give AMQP a moment to flush.
    timer:sleep(1500),
    case catch sys:get_state(erlkoenig_amqp_publisher, 1000) of
        {state, _, Exch, Sent, Dropped, _} ->
            io:format("    publisher: exchange=~s sent=~p dropped=~p~n",
                      [Exch, Sent, Dropped]);
        Other ->
            io:format("    publisher state: ~p~n", [Other])
    end,
    halt(0).
