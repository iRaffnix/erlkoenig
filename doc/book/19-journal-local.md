# Chapter 19 — `:journal.local`

`:journal.local` is the first **service capability** in erlkoenig: a
node-local Unix socket that workloads stream structured log entries
through. Every entry is appended to the SHA-256 hash chain in
`erlkoenig_audit`, optionally signed with Ed25519, and rolled into
the daily HMAC seal. That gives every workload on the node a
tamper-evident journal, for free, with no per-workload setup.

This chapter walks through the capability end-to-end: enable it,
send entries, inspect the audit chain, prove tampering is detected.

> **Foundation.** This chapter assumes the audit hash chain is in
> place (SPEC-AS-005 stages 1-3). If the chapter on the audit log
> doesn't exist yet, the relevant code lives in
> `apps/erlkoenig/src/erlkoenig_audit.erl` and is exercised by
> integration tests 38, 39, 40.

## The shape of an entry

The wire format is one JSON object per newline-terminated line:

```json
{"subject":"web","level":"info","msg":"started","fields":{"port":8080}}
```

| Field      | Type   | Required | Notes                                                      |
|------------|--------|----------|------------------------------------------------------------|
| `subject`  | string | no       | Workload identifier; defaults to `"unknown"` if absent.    |
| `level`    | string | no       | Free-form severity tag. Defaults to `"info"`.              |
| `msg`      | string | no       | Human-readable message.                                    |
| `fields`   | object | no       | Arbitrary structured payload preserved verbatim.           |

The daemon never closes a connection on bad input — a malformed line
is logged and dropped, the next good line is delivered.

## Enabling the daemon

Two pieces of configuration:

```erlang
%% sys.config (or set via application:set_env/3)
{erlkoenig, [
    {audit_path,            "/var/log/erlkoenig/audit.jsonl"},
    {journal_local_path,    "/run/erlkoenig/journal.sock"},
    {journal_local_enabled, true}
]}.
```

When `journal_local_enabled` is `true`, the supervisor adds the
`erlkoenig_journal_local` worker to the boot tree. The default is
`false` so existing installs are unaffected by the new module.

The socket directory must exist and be writable by the BEAM user:

```bash
sudo install -d -o $(id -u) -g $(id -g) -m 0755 /run/erlkoenig
```

## Send your first entry

The simplest client is `socat` plus `jq`:

```bash
echo '{"subject":"hello","msg":"world"}' \
    | socat - UNIX-CONNECT:/run/erlkoenig/journal.sock
```

Verify it landed in the chain:

```bash
tail -n1 /var/log/erlkoenig/audit.jsonl | jq .
```

You should see something like:

```json
{
  "v": 1,
  "seq": 1,
  "ts": "2026-04-19T12:34:56Z",
  "type": "journal",
  "subject": "hello",
  "result": "ok",
  "level": "info",
  "msg": "world",
  "fields": {},
  "conn_id": 17592186044417,
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "this_hash": "9f8e..."
}
```

Note the `v=1` schema version, the chained `prev_hash`/`this_hash`,
and the optional `signature` field (present only when
`audit_signing_key` is configured — see SPEC-AS-005 stage 2).

## Verify the chain

From an Erlang shell on the node:

```erlang
1> erlkoenig_audit:verify_chain("/var/log/erlkoenig/audit.jsonl").
{ok, 1}
```

`{ok, N}` says "N events validated, every link intact". If a public
key is configured, pass it to also verify Ed25519 signatures:

```erlang
2> Pub = erlkoenig_audit:signing_pubkey().
3> erlkoenig_audit:verify_chain("/var/log/erlkoenig/audit.jsonl", Pub).
{ok, 1}
```

## Detect tampering — try it

The whole point of the chain is that you can't quietly change the
past. Edit a single byte in the audit log:

```bash
sed -i 's/"hello"/"helLo"/' /var/log/erlkoenig/audit.jsonl
```

Then re-verify:

```erlang
4> erlkoenig_audit:verify_chain("/var/log/erlkoenig/audit.jsonl").
{error, {chain_break, 1, this_hash_mismatch}}
```

The verifier reports the line number of the first broken link and
why. With signing enabled, you'll see `signature_invalid` instead.

## Daily seal

Once a day (operator-driven for now, cron-triggered later) the live
file is sealed:

```erlang
5> erlkoenig_audit:seal_day().
{ok, #{sealed_path => "/var/log/erlkoenig/audit.jsonl.2026-04-19.sealed",
       event_count => 12_345,
       byte_count  => 4_321_098,
       anchor      => <<"e2c9...">>}}
```

The sealed file is renamed with the UTC date, set to mode `0440`,
and the chain crosses the boundary cleanly: tomorrow's first event
will reference today's seal anchor in `prev_hash`.

Verify a sealed file with the HMAC key:

```erlang
6> {ok, HmacKey} = file:read_file("/etc/erlkoenig/audit-hmac.key").
7> erlkoenig_audit:verify_seal(
       "/var/log/erlkoenig/audit.jsonl.2026-04-19.sealed", HmacKey).
{ok, #{event_count => 12_345, ...}}
```

## End-to-end exercise

The integration test under `tests/integration/41_journal_local.escript`
runs the full path: bind socket → connect two clients → garbage
input handling → chain verification. Run it locally:

```bash
make erl
tests/integration/41_journal_local.escript
```

Output:

```
=== Test 41: journal.local ===

[OK  ] daemon binds the configured socket path
[OK  ] single client streams 3 entries -> 3 audit events
[OK  ] two concurrent clients stream cleanly into the chain
[OK  ] garbage lines are dropped, good lines still arrive
[OK  ] full audit log validates as a hash chain

=== Test 41 passed ===
```

This is also the script you should read when you want to know what
the runtime guarantees in practice.

## What's next

`:journal.local` is the first capability of eleven planned (see the
strategy memo `2026-04-19-node-sovereign-architecture` in
`erlkoenigin/strategy/`). The next ones to land follow the same
pattern: a Unix-socket service, a documented JSON-line protocol, and
audit-chained side effects.

| Capability         | Purpose                                  | Status   |
|--------------------|------------------------------------------|----------|
| `:journal.local`   | Structured log forwarder                 | live     |
| `:dns.local`       | Resolver with policy (planned promotion) | partial  |
| `:postgres.local`  | Tenant-isolated Postgres entry point     | planned  |
| ...                | (see strategy memo for full catalog)     |          |
