# Chapter 20 — Customer-side Audit Verification

`audit-verifier` is a statically-linked Go binary the customer
hands to their auditor. It reads the same audit JSONL files
`erlkoenig_audit` writes and recomputes the SHA-256 hash chain,
the Ed25519 signatures, and the daily HMAC seal — independently,
offline, with no network calls and no language toolchain on the
target host.

This chapter is **playable**. Copy the commands, run them, watch
the output. ~15 minutes from a fresh checkout to a verified seal
plus three tampering exercises.

## Why a separate binary

The whole point of customer-side verification is **independence**.
The customer should not have to trust the same runtime that
produced the log — that's circular. Two implementations in two
languages, each recomputing the chain from first principles,
dramatically reduce the chance of a hidden agreement that lets
tampering through.

The Go side is intentionally tiny (3 files, ~550 LOC):

  * `canonical.go` — the canonical JSON encoder, byte-for-byte
    identical to Erlang's `erlkoenig_audit:canonical_json/1`.
  * `verify.go` — chain walking, Ed25519, HMAC.
  * `main.go` — three CLI subcommands and documented exit codes.

An auditor with no Erlang background can read the Go side
end-to-end in 30 minutes and know exactly what is being checked.

## What it verifies

For every line in the audit log:

  1. **prev_hash links** — must equal the previous line's
     `this_hash` (or 64 zeros for genesis, or the seal anchor when
     continuing past a sealed file).
  2. **this_hash recomputation** — strip `this_hash` and `signature`,
     encode canonically, SHA-256, must equal the stored value.
  3. **Ed25519 signature** (when `--pubkey` given) — verify against
     the raw 32 bytes of `this_hash`.
  4. **Seal HMAC** (when verifying a `.sealed` file) — recompute
     HMAC-SHA-256 over the first `byte_count` bytes and match the
     seal event's `hmac` field.

Steps 1-3 mirror `erlkoenig_audit:verify_chain/2` (→ Chapter 19);
step 4 mirrors `erlkoenig_audit:verify_seal/2`.

## Exit codes

| Code | Meaning                       |
|------|-------------------------------|
| `0`  | verification succeeded        |
| `1`  | hash chain broken             |
| `2`  | Ed25519 signature invalid     |
| `3`  | HMAC mismatch on sealed file  |
| `4`  | argument or I/O error         |

Operators wire these directly into monitoring: any non-zero exit
from a daily verification cron is a security incident.

---

## Quick run — one command

If you just want to see all seven verification + tampering
scenarios fly past in one shot:

```bash
make verifier            # build the binary once
cd dsl
mix run ../examples/audit_verifier_demo.exs
```

The script generates a fresh sandbox, signs and seals an audit
log via the Erlang implementation, then runs the Go verifier in
all four happy-path modes plus three tamper exercises:

```
=== verification results ===
  [PASS] chain only (no key)  (expected exit 0, got 0)
  [PASS] chain + signatures  (expected exit 0, got 0)
  [PASS] seal HMAC  (expected exit 0, got 0)
  [PASS] verify-day (combined)  (expected exit 0, got 0)
  [PASS] tamper: byte change in event line  (expected exit 1, got 1)
  [PASS] tamper: wrong public key  (expected exit 2, got 2)
  [PASS] tamper: wrong HMAC key  (expected exit 3, got 3)

=== demo passed (7/7) ===
```

That's the whole chapter compressed to one command. Read on for
the same flow broken into copy-paste steps you can play with
yourself.

> **Doubles as a regression test.** `make verifier-xcheck` wraps
> the same demo and exits non-zero on any deviation. Wire it into
> CI alongside `make check` to catch any cross-language drift on
> canonical JSON, hash chain, signature, or seal format the
> moment either side changes.

---

## Step 0 — Build

```bash
make verifier
```

Produces `dist/audit-verifier`, fully static (`ldd` says
`not a dynamic executable`), currently ~2.4 MB stripped.

```bash
file dist/audit-verifier            # ELF, statically linked, stripped
ldd dist/audit-verifier             # not a dynamic executable
du -h dist/audit-verifier           # 2.4M
```

Sandbox so the rest of the chapter doesn't touch system locations:

```bash
mkdir -p /tmp/ek-ch20
```

## Step 1 — Produce a signed + sealed audit log

We need keys for both Ed25519 signing and HMAC seal:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    file:write_file("/tmp/ek-ch20/sign.key", Priv),
    file:write_file("/tmp/ek-ch20/sign.pub", Pub),
    file:write_file("/tmp/ek-ch20/hmac.key",
                    crypto:strong_rand_bytes(32)),
    halt(0).
'
```

Now log a couple of events, then seal the day:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    application:set_env(erlkoenig, audit_path, "/tmp/ek-ch20/a.jsonl"),
    application:set_env(erlkoenig, audit_signing_key, "/tmp/ek-ch20/sign.key"),
    application:set_env(erlkoenig, audit_hmac_key, "/tmp/ek-ch20/hmac.key"),
    {ok, _} = erlkoenig_audit:start_link(),
    erlkoenig_audit:log(#{type => morning, subject => <<"task1">>, result => ok}),
    erlkoenig_audit:log(#{type => morning, subject => <<"task2">>, result => ok}),
    timer:sleep(150),
    {ok, Info} = erlkoenig_audit:seal_day(),
    io:format("sealed: ~s~n", [maps:get(sealed_path, Info)]),
    halt(0).
'
```

Output (date will differ):

```
sealed: /tmp/ek-ch20/a.jsonl.2026-04-19.sealed
```

The sealed file holds 3 lines: two `morning` events plus an
`audit.seal` event with the HMAC + counts.

## Step 2 — Verify the chain

```bash
SEALED=/tmp/ek-ch20/a.jsonl.2026-04-19.sealed
dist/audit-verifier verify-chain "$SEALED"; echo "exit=$?"
```

Expected:

```
ok: 3 event(s), chain head <hex>
    last event is audit.seal — anchor for next day: <hex>
exit=0
```

The verifier walked all 3 lines, recomputed each `this_hash`,
checked every `prev_hash` link. No signature check yet — that's
the next step.

## Step 3 — Verify chain + signatures

```bash
dist/audit-verifier verify-chain --pubkey /tmp/ek-ch20/sign.pub "$SEALED"
echo "exit=$?"
```

Same `ok` line, exit 0. Each event's `signature` field was
verified against the public key over the raw 32 bytes of
`this_hash`. The customer holds the public key and can re-run
this at any time.

## Step 4 — Verify the seal HMAC

```bash
dist/audit-verifier verify-seal --hmac-key /tmp/ek-ch20/hmac.key "$SEALED"
echo "exit=$?"
```

Expected:

```
ok: seal verified — 2 event(s), <N> bytes, anchor <hex>
exit=0
```

The verifier recomputed HMAC-SHA-256 over the first `byte_count`
bytes of the file (everything BEFORE the seal event line) and
matched it against the seal event's `hmac` field.

## Step 5 — One-shot full validation

```bash
dist/audit-verifier verify-day \
    --pubkey   /tmp/ek-ch20/sign.pub \
    --hmac-key /tmp/ek-ch20/hmac.key \
    "$SEALED"
echo "exit=$?"
```

Expected:

```
ok: chain + seal verified — 2 events, <N> bytes, anchor <hex>
exit=0
```

Chain + signatures + HMAC in one call. This is the operator/
auditor's daily habit.

## Step 6 — Tampering exercises

The whole point is that you can't quietly change the past.
Three exercises, one per cryptographic layer.

### 6a — Byte-level tamper → chain break

```bash
cp "$SEALED" /tmp/ek-ch20/tampered.sealed
chmod +w /tmp/ek-ch20/tampered.sealed
sed -i 's/"task1"/"TASK1"/' /tmp/ek-ch20/tampered.sealed
dist/audit-verifier verify-chain /tmp/ek-ch20/tampered.sealed
echo "exit=$?"
```

Expected:

```
FAIL: line 1: chain break — this_hash mismatch (stored "..." recomputed "...")
exit=1
```

A single byte changed → SHA-256 differs → chain link breaks at
the exact line. Exit 1 = the operator's monitoring page lights
up immediately.

### 6b — Wrong public key → signature invalid

Generate a different keypair and try to verify with it:

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    {P, _} = crypto:generate_key(eddsa, ed25519),
    file:write_file("/tmp/ek-ch20/wrong.pub", P),
    halt(0).
'
dist/audit-verifier verify-chain --pubkey /tmp/ek-ch20/wrong.pub "$SEALED"
echo "exit=$?"
```

Expected:

```
FAIL: line 1: signature: ed25519 verify failed
exit=2
```

Exit 2 — the chain itself is fine, but the signature was made by
a different key. This catches an attacker who recomputed
`this_hash` correctly after tampering but couldn't sign because
they don't have the private key (TPM-sealed in production).

### 6c — Wrong HMAC key → seal mismatch

```bash
erl -pa _build/default/lib/*/ebin -noshell -eval '
    file:write_file("/tmp/ek-ch20/wrong.hmac",
                    crypto:strong_rand_bytes(32)),
    halt(0).
'
dist/audit-verifier verify-seal --hmac-key /tmp/ek-ch20/wrong.hmac "$SEALED"
echo "exit=$?"
```

Expected:

```
FAIL: seal hmac mismatch (expected "..." got "...")
exit=3
```

Exit 3 — same chain, same signatures, wrong HMAC. The customer
knows the seal wasn't produced by their key.

## Step 7 — Wire it into monitoring

A trivial daily cron that pages on any non-zero exit:

```bash
#!/bin/bash
# /etc/cron.daily/erlkoenig-audit-verify
set -e
SEALED=$(ls -1t /var/log/erlkoenig/audit.jsonl.*.sealed | head -1)
/usr/local/bin/audit-verifier verify-day \
    --pubkey   /etc/erlkoenig/audit-sign.pub \
    --hmac-key /etc/erlkoenig/audit-hmac.key \
    "$SEALED"
# Exit code propagates to cron; non-zero triggers your alerting.
```

The Go binary is small enough to ship inside the customer's own
deployment artefacts and re-run during compliance audits without
any erlkoenig running on the target host.

## Cleanup

```bash
rm -rf /tmp/ek-ch20
```

## What you proved

- The Go verifier and the Erlang implementation agree byte-for-byte
  on canonical JSON (any drift would have produced a hash mismatch
  in step 2).
- Every cryptographic layer in SPEC-AS-005 fails loudly to an
  independent observer — chain, signature, seal, each with its
  own exit code.
- The customer-side verification story works without erlkoenig,
  without Erlang, without snapd, without anything beyond a vanilla
  Linux kernel and the 2.4 MB binary.

## What this chapter does NOT cover

- **Cross-day meta-chain verification.** When you have multiple
  `.sealed` files for consecutive days, the seal event of day N
  exposes an anchor that becomes the genesis `prev_hash` for day
  N+1. Pass `--start-prev <anchor>` to `verify-chain` on the next
  day's file to extend the verification across the boundary. The
  ergonomic wrapper (`verify-month`) is on the roadmap.
- **Bulk verification across many tenants.** The current binary
  walks one file at a time. A multi-file driver script in shell or
  Go is straightforward; there's no architectural change needed.
