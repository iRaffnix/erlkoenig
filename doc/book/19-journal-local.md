# Chapter 19 — `:journal.local`

`:journal.local` is the first **service capability** in erlkoenig: a
node-local Unix socket that workloads stream structured log entries
through. Every entry is appended to the SHA-256 hash chain in
`erlkoenig_audit`, optionally signed with Ed25519, and rolled into
the daily HMAC seal. That gives every workload on the node a
tamper-evident journal, for free, with no per-workload setup.

This chapter is **playable**. Copy the commands, run them, watch
the output. ~20 minutes from a fresh checkout to a verified chain.
You don't need root, you don't need a VM, you don't need a network.

## What you'll prove

- Single-byte tampering in the audit log is detected at the line
  that broke.
- With an Ed25519 key configured, every event is also signed; the
  customer can verify offline with the public key alone.
- The daily HMAC seal binds the day's bytes; the seal event becomes
  the anchor for the next day's first event, so the chain crosses
  file boundaries.
- `:journal.local` is just a thin Unix-socket front-end that
  delivers structured entries into all of the above. Workloads opt
  in by writing JSON lines to the socket; everything else is free.

## The shape of an entry

Wire format is one JSON object per newline-terminated line:

```json
{"subject":"web","level":"info","msg":"started","fields":{"port":8080}}
```

| Field      | Type   | Required | Notes                                                      |
|------------|--------|----------|------------------------------------------------------------|
| `subject`  | string | no       | Workload identifier; defaults to `"unknown"` if absent.    |
| `level`    | string | no       | Free-form severity tag. Defaults to `"info"`.              |
| `msg`      | string | no       | Human-readable message.                                    |
| `fields`   | object | no       | Arbitrary structured payload preserved verbatim.           |

The daemon never closes a connection on bad input — a malformed
line is logged and dropped, the next good line is delivered.

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
mkdir -p /tmp/ek-ch19
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

**Try it manually** — open an Erlang shell:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    application:set_env(erlkoenig, audit_path, "/tmp/ek-ch19/a.jsonl"),
    {ok, _} = erlkoenig_audit:start_link(),
    erlkoenig_audit:log(#{type => hello, subject => <<"world">>, result => ok}),
    erlkoenig_audit:log(#{type => hello, subject => <<"again">>, result => ok}),
    timer:sleep(100),
    io:format("verify_chain => ~p~n",
        [erlkoenig_audit:verify_chain("/tmp/ek-ch19/a.jsonl")]),
    halt(0).
'
```

Expected output:

```
verify_chain => {ok,2}
```

Inspect the file (each line is one JSON event):

```bash
cat /tmp/ek-ch19/a.jsonl
```

Each line carries these chain-related fields:

| Field        | Example                                    |
|--------------|--------------------------------------------|
| `v`          | `1` (schema version)                       |
| `seq`        | monotonic counter starting at 1            |
| `prev_hash`  | hex SHA-256 of the prior event             |
| `this_hash`  | hex SHA-256 of this event (sans this_hash) |

The genesis event has `prev_hash` = 64 zeros.

Now break it:

```bash
sed -i 's/"world"/"WORLD"/' /tmp/ek-ch19/a.jsonl
erl -pa _build/default/lib/*/ebin -noshell -eval '
    io:format("after tamper => ~p~n",
        [erlkoenig_audit:verify_chain("/tmp/ek-ch19/a.jsonl")]),
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
rm -f /tmp/ek-ch19/*.jsonl
```

---

## Step 2 — Add Ed25519 signatures (stage 2)

Generate a fresh keypair, write the private key to disk:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    file:write_file("/tmp/ek-ch19/sign.key", Priv),
    file:write_file("/tmp/ek-ch19/sign.pub", Pub),
    halt(0).
'
```

Re-run with signing enabled, then verify with right and wrong keys:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    application:set_env(erlkoenig, audit_path, "/tmp/ek-ch19/b.jsonl"),
    application:set_env(erlkoenig, audit_signing_key, "/tmp/ek-ch19/sign.key"),
    {ok, _} = erlkoenig_audit:start_link(),
    erlkoenig_audit:log(#{type => signed, subject => <<"first">>, result => ok}),
    erlkoenig_audit:log(#{type => signed, subject => <<"second">>, result => ok}),
    timer:sleep(100),
    {ok, Pub} = file:read_file("/tmp/ek-ch19/sign.pub"),
    io:format("with key   => ~p~n",
        [erlkoenig_audit:verify_chain("/tmp/ek-ch19/b.jsonl", Pub)]),
    {WrongPub, _} = crypto:generate_key(eddsa, ed25519),
    io:format("wrong key  => ~p~n",
        [erlkoenig_audit:verify_chain("/tmp/ek-ch19/b.jsonl", WrongPub)]),
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
    file:write_file("/tmp/ek-ch19/hmac.key",
                    crypto:strong_rand_bytes(32)),
    halt(0).
'

erl -pa _build/default/lib/*/ebin -noshell -eval '
    application:set_env(erlkoenig, audit_path, "/tmp/ek-ch19/c.jsonl"),
    application:set_env(erlkoenig, audit_signing_key, "/tmp/ek-ch19/sign.key"),
    application:set_env(erlkoenig, audit_hmac_key, "/tmp/ek-ch19/hmac.key"),
    {ok, _} = erlkoenig_audit:start_link(),
    erlkoenig_audit:log(#{type => morning, subject => <<"task1">>, result => ok}),
    erlkoenig_audit:log(#{type => morning, subject => <<"task2">>, result => ok}),
    timer:sleep(100),
    {ok, Info} = erlkoenig_audit:seal_day(),
    io:format("sealed => ~p~n", [Info]),
    {ok, Hmac} = file:read_file("/tmp/ek-ch19/hmac.key"),
    SealedPath = maps:get(sealed_path, Info),
    io:format("verify_seal => ~p~n",
        [erlkoenig_audit:verify_seal(SealedPath, Hmac)]),
    halt(0).
'
```

Expected (anchor hash will differ):

```
sealed => #{anchor => <<"...">>,byte_count => ...,event_count => 2,
            sealed_path => "/tmp/ek-ch19/c.jsonl.2026-04-19.sealed"}
verify_seal => {ok,#{anchor => <<"...">>,byte_count => ...,event_count => 2}}
```

The live file (`c.jsonl`) is empty after the seal — fresh day. The
sealed file is mode `0440` and ends with an `audit.seal` event
carrying the HMAC and counts. List both:

```bash
ls -l /tmp/ek-ch19/c.jsonl*
```

```
-rw-rw-r-- 1 you you   0 ... c.jsonl
-r--r----- 1 you you 879 ... c.jsonl.2026-04-19.sealed
```

---

## Step 4 — `:journal.local` (the first service capability)

Daemon and client in a single Erlang invocation so the chapter
works without external tools. The daemon listens on a Unix socket;
the client connects, sends two JSON-line entries, and we then read
them back from the audit chain.

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    application:set_env(erlkoenig, audit_path, "/tmp/ek-ch19/d.jsonl"),
    application:set_env(erlkoenig, journal_local_path,
                        "/tmp/ek-ch19/journal.sock"),
    {ok, _} = erlkoenig_audit:start_link(),
    {ok, _} = erlkoenig_journal_local:start_link(),
    Sock = element(2, gen_tcp:connect(
        {local, "/tmp/ek-ch19/journal.sock"}, 0,
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
        [erlkoenig_audit:verify_chain("/tmp/ek-ch19/d.jsonl")]),
    halt(0).
'
```

Expected:

```
verify_chain => {ok,2}
```

Now look at what landed in the chain:

```bash
cat /tmp/ek-ch19/d.jsonl
```

Each line carries the `journal` type, the workload's claimed
subject (`web`), the level/msg/fields you sent, and the chain
fields (`prev_hash`/`this_hash`). The first event references
genesis (64 zeros); the second references the first.

**With `socat` installed** the same thing from the command line
(start the daemon in one shell, run these in another):

```bash
echo '{"subject":"web","level":"info","msg":"started"}' \
    | socat - UNIX-CONNECT:/tmp/ek-ch19/journal.sock
```

For a complete pure-Erlang example with concurrent clients and
malformed input handling, read
`tests/integration/41_journal_local.escript`.

---

## Step 5 — One-shot DSL → daemons → workload → verify

Until now you've spoken to the daemon directly. In a real
deployment the workload sits in a container that declares its
dependency in a DSL stack file:

```elixir
container :web do
  binary "/opt/bin/web"
  requires :"journal.local"
end
```

`requires :"journal.local"` does three things at term-generation
time:

1. Adds `:"journal.local"` to the container's `:requires` field
   (informational — operators see what each container depends on).
2. Bind-mounts the host socket
   `/run/erlkoenig/journal.sock` into the container at
   `/run/journal.sock`.
3. Sets the env var `JOURNAL_LOCAL_SOCK=/run/journal.sock` so the
   workload code finds the socket without hard-coding a path.

The workload's only job is to open `JOURNAL_LOCAL_SOCK` and write
JSON lines.

The repository ships `examples/journal_demo.exs` which ties the
whole flow together in one file — DSL stack, daemon startup,
simulated workload, chain verification. Run it:

```bash
cd dsl
mix run ../examples/journal_demo.exs
```

Expected output:

```
=== DSL output ===
requires      : [:"journal.local"]
env injected  : JOURNAL_LOCAL_SOCK = /run/journal.sock
socket_mount  : %{host: "/run/erlkoenig/journal.sock", read_only: false,
                  container: "/run/journal.sock"}

=== daemons up ===
audit_path : /tmp/ek-journal-demo-.../audit.jsonl
socket     : /tmp/ek-journal-demo-.../journal.sock

=== verify_chain ===
{:ok, 3}

=== chain content (3 events) ===
seq=1  type=journal  subject=web  msg=starting
seq=2  type=journal  subject=web  msg=ready
seq=3  type=journal  subject=web  msg=slow request

=== demo passed ===
```

What just happened, top to bottom:

| Phase                | What the demo did                                                                |
|----------------------|----------------------------------------------------------------------------------|
| DSL output           | Compiled the one-container stack and dumped `:requires`, env, socket mount.      |
| daemons up           | Started `:erlkoenig_audit` and `:erlkoenig_journal_local` on a `/tmp` sandbox.   |
| workload             | Opened the env-var path the DSL set, sent three JSON-line entries, closed.       |
| verify_chain         | Re-walked the audit log byte-by-byte; `{:ok, 3}` means "3 events, links intact". |
| chain content        | Pretty-printed the journal-typed events the workload produced.                   |

Unknown capability names fail at compile-time:

```elixir
container :bad do
  binary "/opt/bin/bad"
  requires :"nonsense.local"
end
# ** (ArgumentError) unknown capability :"nonsense.local"; known: [:"journal.local"]
```

> **Honesty.** The demo runs without containers, so the workload
> uses the host socket path directly (the DSL env var is overridden
> in-process). In production, the runtime sets up the bind mount
> the DSL describes (`socket_mounts`) and the env var inside the
> container points at the in-namespace path. The DSL term is the
> same either way; only the path resolution differs. Wiring the
> runtime to consume `:socket_mounts` is the next piece of work
> tracked in the roadmap.

## Step 6 — All four integration tests in a row

```bash
for t in 38 39 40 41; do
    tests/integration/${t}_audit_*.escript 2>/dev/null \
        || tests/integration/${t}_journal_local.escript
done
```

You should see four `=== Test NN passed ===` lines. That's the same
suite CI runs on every PR.

---

## Production deployment

For an installed node, configure all three knobs in `sys.config`:

```erlang
{erlkoenig, [
    {audit_path,            "/var/log/erlkoenig/audit.jsonl"},
    {audit_signing_key,     "/etc/erlkoenig/audit-sign.key"},
    {audit_hmac_key,        "/etc/erlkoenig/audit-hmac.key"},
    {journal_local_path,    "/run/erlkoenig/journal.sock"},
    {journal_local_enabled, true}
]}.
```

When `journal_local_enabled` is `true`, the supervisor adds the
`erlkoenig_journal_local` worker to the boot tree. Default is
`false` so existing installs are unaffected by the new module.

The socket directory must exist and be writable by the BEAM user:

```bash
sudo install -d -o $(id -u) -g $(id -g) -m 0755 /run/erlkoenig
```

## Cleanup

```bash
rm -rf /tmp/ek-ch19
```

## What's next

`:journal.local` is the first capability of eleven planned (see the
strategy memo `2026-04-19-node-sovereign-architecture` in
`erlkoenigin/strategy/`). The next ones to land follow the same
pattern: a Unix-socket service, a documented JSON-line protocol,
and audit-chained side effects.

| Capability         | Purpose                                  | Status   |
|--------------------|------------------------------------------|----------|
| `:journal.local`   | Structured log forwarder                 | live     |
| `:dns.local`       | Resolver with policy (planned promotion) | partial  |
| `:postgres.local`  | Tenant-isolated Postgres entry point     | planned  |
| ...                | (see strategy memo for full catalog)     |          |

Spec for the audit foundation: `erlkoenigin/specs/ai-sandbox/SPEC-AS-005-audit-trail.md`.
Stage 4 (offline Go verifier, customer-deliverable): planned.
