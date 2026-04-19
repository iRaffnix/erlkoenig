# Tutorial 1 — Audit chain + `:journal.local` from scratch

In this tutorial you'll:

1. Build the runtime
2. Walk the audit hash chain end-to-end (events → chain → tampering)
3. Add Ed25519 signatures
4. Add the daily HMAC seal
5. Stream entries from a workload through `:journal.local`
6. Verify everything by hand from an Erlang shell

You don't need root, you don't need a VM, you don't need a network.
A laptop with Erlang/OTP 28+ and `make` is enough.

> Estimated time: 20 minutes.

---

## Step 0 — Setup

```bash
git clone https://github.com/iRaffnix/erlkoenig.git
cd erlkoenig
make erl
```

Expected: rebar3 compiles cleanly. The build leaves the BEAM files
under `_build/default/lib/erlkoenig/ebin/`.

Set a sandbox path so you don't touch system locations:

```bash
export EK_AUDIT_DIR=/tmp/ek-tutorial-1
mkdir -p "$EK_AUDIT_DIR"
```

---

## Step 1 — The hash chain (no signing, no seal)

Run integration test 38. It logs three events, verifies the chain,
then tampers with one byte and proves verification catches it.

```bash
tests/integration/38_audit_hash_chain.escript
```

Expected last line:

```
=== Test 38 passed ===
```

What just happened — open the audit log the test wrote (the path is
printed by the test if you watch carefully; here we know the
pattern):

```bash
ls /tmp/erlkoenig_audit_test_38_* | head -1
```

Each line is a JSON event with these chain-related fields:

| Field        | Example                                    |
|--------------|--------------------------------------------|
| `v`          | `1` (schema version)                       |
| `seq`        | monotonic counter starting at 1            |
| `prev_hash`  | hex SHA-256 of the prior event             |
| `this_hash`  | hex SHA-256 of this event (sans this_hash) |

Genesis event has `prev_hash` = 64 zeros.

**Try it manually** — open an Erlang shell:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    application:set_env(erlkoenig, audit_path, "/tmp/ek-tutorial-1/a.jsonl"),
    {ok, _} = erlkoenig_audit:start_link(),
    erlkoenig_audit:log(#{type => hello, subject => <<"world">>, result => ok}),
    erlkoenig_audit:log(#{type => hello, subject => <<"again">>, result => ok}),
    timer:sleep(100),
    io:format("verify_chain => ~p~n",
        [erlkoenig_audit:verify_chain("/tmp/ek-tutorial-1/a.jsonl")]),
    halt(0).
'
```

Expected output:

```
verify_chain => {ok,2}
```

Inspect the file:

```bash
cat /tmp/ek-tutorial-1/a.jsonl | jq .
```

Now break it:

```bash
sed -i 's/"world"/"WORLD"/' /tmp/ek-tutorial-1/a.jsonl
erl -pa _build/default/lib/*/ebin -noshell -eval '
    io:format("after tamper => ~p~n",
        [erlkoenig_audit:verify_chain("/tmp/ek-tutorial-1/a.jsonl")]),
    halt(0).
'
```

Expected:

```
after tamper => {error,{chain_break,1,this_hash_mismatch}}
```

The verifier names the broken line and why. That's the whole point
of stage 1.

Clean up before moving on:

```bash
rm -f /tmp/ek-tutorial-1/*.jsonl
```

---

## Step 2 — Add Ed25519 signatures (stage 2)

Generate a fresh keypair, write the private key to disk, configure
the audit module to use it:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    file:write_file("/tmp/ek-tutorial-1/sign.key", Priv),
    file:write_file("/tmp/ek-tutorial-1/sign.pub", Pub),
    halt(0).
'
```

Re-run with signing enabled:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    application:set_env(erlkoenig, audit_path, "/tmp/ek-tutorial-1/b.jsonl"),
    application:set_env(erlkoenig, audit_signing_key, "/tmp/ek-tutorial-1/sign.key"),
    {ok, _} = erlkoenig_audit:start_link(),
    erlkoenig_audit:log(#{type => signed, subject => <<"first">>, result => ok}),
    erlkoenig_audit:log(#{type => signed, subject => <<"second">>, result => ok}),
    timer:sleep(100),
    {ok, Pub} = file:read_file("/tmp/ek-tutorial-1/sign.pub"),
    io:format("with key   => ~p~n",
        [erlkoenig_audit:verify_chain("/tmp/ek-tutorial-1/b.jsonl", Pub)]),
    {WrongPub, _} = crypto:generate_key(eddsa, ed25519),
    io:format("wrong key  => ~p~n",
        [erlkoenig_audit:verify_chain("/tmp/ek-tutorial-1/b.jsonl", WrongPub)]),
    halt(0).
'
```

Expected:

```
with key   => {ok,2}
wrong key  => {error,{signature_invalid,1,ed25519_verify_failed}}
```

Each event now has a 128-hex-char `signature` field (Ed25519 over
the raw 32 bytes of `this_hash`). The customer keeps the public key
and can run the same `verify_chain/2` offline.

---

## Step 3 — Daily HMAC seal (stage 3)

Generate a 32-byte HMAC key, then seal:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    file:write_file("/tmp/ek-tutorial-1/hmac.key",
                    crypto:strong_rand_bytes(32)),
    halt(0).
'

erl -pa _build/default/lib/*/ebin -noshell -eval '
    application:set_env(erlkoenig, audit_path, "/tmp/ek-tutorial-1/c.jsonl"),
    application:set_env(erlkoenig, audit_signing_key, "/tmp/ek-tutorial-1/sign.key"),
    application:set_env(erlkoenig, audit_hmac_key, "/tmp/ek-tutorial-1/hmac.key"),
    {ok, _} = erlkoenig_audit:start_link(),
    erlkoenig_audit:log(#{type => morning, subject => <<"task1">>, result => ok}),
    erlkoenig_audit:log(#{type => morning, subject => <<"task2">>, result => ok}),
    timer:sleep(100),
    {ok, Info} = erlkoenig_audit:seal_day(),
    io:format("sealed => ~p~n", [Info]),
    {ok, Hmac} = file:read_file("/tmp/ek-tutorial-1/hmac.key"),
    SealedPath = maps:get(sealed_path, Info),
    io:format("verify_seal => ~p~n",
        [erlkoenig_audit:verify_seal(SealedPath, Hmac)]),
    halt(0).
'
```

Expected (anchor hash will differ):

```
sealed => #{anchor => <<"...">>,byte_count => ...,event_count => 2,
            sealed_path => "/tmp/ek-tutorial-1/c.jsonl.2026-04-19.sealed"}
verify_seal => {ok,#{anchor => <<"...">>,byte_count => ...,event_count => 2}}
```

The live file (`c.jsonl`) is empty after the seal — fresh day. The
sealed file is mode `0440` and ends with an `audit.seal` event
carrying the HMAC and counts. List both:

```bash
ls -l /tmp/ek-tutorial-1/c.jsonl*
```

```
-rw-rw-r-- 1 you you   0 ... c.jsonl
-r--r----- 1 you you 879 ... c.jsonl.2026-04-19.sealed
```

---

## Step 4 — `:journal.local` (the first service capability)

We'll start the daemon and a client in a single Erlang invocation
so the tutorial works without external tools. The daemon listens on
a Unix socket; the client connects, sends two JSON-line entries,
and we then read them back from the audit chain.

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    application:set_env(erlkoenig, audit_path, "/tmp/ek-tutorial-1/d.jsonl"),
    application:set_env(erlkoenig, journal_local_path,
                        "/tmp/ek-tutorial-1/journal.sock"),
    {ok, _} = erlkoenig_audit:start_link(),
    {ok, _} = erlkoenig_journal_local:start_link(),
    Sock = element(2, gen_tcp:connect(
        {local, "/tmp/ek-tutorial-1/journal.sock"}, 0,
        [binary, {packet, line}, {active, false}])),
    Send = fun(M) ->
        gen_tcp:send(Sock, [json:encode(M), $\n])
    end,
    Send(#{<<"subject">> => <<"web">>, <<"level">> => <<"info">>,
           <<"msg">> => <<"started">>, <<"fields">> => #{<<"port">> => 8080}}),
    Send(#{<<"subject">> => <<"web">>, <<"level">> => <<"warn">>,
           <<"msg">> => <<"slow">>, <<"fields">> => #{<<"ms">> => 1234}}),
    gen_tcp:close(Sock),
    timer:sleep(200),
    io:format("verify_chain => ~p~n",
        [erlkoenig_audit:verify_chain("/tmp/ek-tutorial-1/d.jsonl")]),
    halt(0).
' 2>&1 | tail -3
```

Expected:

```
verify_chain => {ok,2}
```

Now look at what landed in the chain:

```bash
cat /tmp/ek-tutorial-1/d.jsonl
```

Each line includes the `journal` type, the workload's claimed
subject (`web`), the level/msg/fields you sent, and the chain
fields (`prev_hash`/`this_hash`). The first event references genesis
(64 zeros); the second references the first.

**With `socat` installed** the same effect from the command line
(start the daemon in one shell, run these in another):

```bash
echo '{"subject":"web","level":"info","msg":"started"}' \
    | socat - UNIX-CONNECT:/tmp/ek-tutorial-1/journal.sock
```

For a complete pure-Erlang example with concurrent clients and
malformed input handling, read `tests/integration/41_journal_local.escript`.

---

## Step 5 — All four integration tests in a row

```bash
for t in 38 39 40 41; do
    tests/integration/${t}_audit_*.escript 2>/dev/null \
        || tests/integration/${t}_journal_local.escript
done
```

You should see four `=== Test NN passed ===` lines. That's the same
suite CI runs on every PR.

---

## Cleanup

```bash
rm -rf /tmp/ek-tutorial-1
```

---

## What you proved

- Every audit event is chained by SHA-256 — single-byte tampering
  is detectable at the line that broke.
- With an Ed25519 key configured, every event is also signed; the
  customer can verify offline with the public key alone.
- A daily HMAC seal binds the day's bytes; the seal event becomes
  the anchor for the next day's first event, so the chain crosses
  file boundaries.
- `:journal.local` is just a thin Unix-socket front-end that
  delivers structured entries into all of the above. Workloads opt
  in by writing JSON lines to the socket; everything else is free.

## Where to go next

- Reference: [Chapter 19 — `:journal.local`](../doc/book/19-journal-local.md)
- Spec: `erlkoenigin/specs/ai-sandbox/SPEC-AS-005-audit-trail.md`
- Stage 4 (offline Go verifier, customer-deliverable): planned
