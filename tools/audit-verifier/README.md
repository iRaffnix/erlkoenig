# audit-verifier

Offline verifier for SPEC-AS-005 audit logs. A statically-linked
Go binary the customer hands to their auditor — no network, no
external dependencies, no language toolchain on the target host.

## Build

```bash
make verifier        # from the repo root, produces dist/audit-verifier
# or directly:
cd tools/audit-verifier && CGO_ENABLED=0 go build -ldflags="-s -w" -o audit-verifier .
```

The binary is fully static (`ldd` says `not a dynamic executable`)
and currently weighs **~2.4 MB** stripped.

## Usage

```bash
# Hash chain only (no Ed25519 verification needed)
audit-verifier verify-chain audit.jsonl

# Hash chain + Ed25519 signatures
audit-verifier verify-chain --pubkey audit-sign.pub audit.jsonl

# Sealed file: verify the day's HMAC
audit-verifier verify-seal --hmac-key audit-hmac.key audit.jsonl.YYYY-MM-DD.sealed

# Full validation: chain + signatures + HMAC seal in one call
audit-verifier verify-day --pubkey audit-sign.pub --hmac-key audit-hmac.key \
                          audit.jsonl.YYYY-MM-DD.sealed
```

The pubkey and HMAC key files are raw 32-byte binary (the same
format `erlkoenig_audit:load_signing_key/0` reads).

## Exit codes

| Code | Meaning                                  |
|------|------------------------------------------|
| `0`  | verification succeeded                   |
| `1`  | hash chain broken                        |
| `2`  | Ed25519 signature invalid                |
| `3`  | HMAC mismatch on sealed file             |
| `4`  | argument or I/O error                    |

Operators wire these directly into monitoring: any non-zero exit
from a daily verification cron is a security incident.

## What it verifies

For each line in the audit log:

  1. **prev_hash links** — the line's `prev_hash` must equal the
     previous line's `this_hash` (or 64 zeros for the genesis event,
     or the seal anchor when continuing past a sealed file).
  2. **this_hash recomputation** — strip `this_hash` and `signature`
     from the event, encode canonically (sorted-keys JSON, no
     whitespace, escape `"`/`\`/`\n`), SHA-256 → must equal the
     stored `this_hash`.
  3. **Ed25519 signature** (when `--pubkey` given) — verify the
     stored `signature` against the raw 32 bytes of `this_hash`.
  4. **Seal HMAC** (when verifying a `.sealed` file) — recompute
     HMAC-SHA-256 over the first `byte_count` bytes of the file
     and compare to the seal event's `hmac` field.

Steps 1-3 mirror `erlkoenig_audit:verify_chain/2`; step 4 mirrors
`erlkoenig_audit:verify_seal/2`. The Go and Erlang implementations
must agree byte-for-byte on canonical JSON for verification to
interoperate — see `canonical.go` for the encoder.

## Why a separate binary

The whole point of customer-side verification is **independence**.
The customer should not have to trust the same runtime that
produced the log. Two implementations in two languages, each
recomputing the chain from first principles, dramatically reduce
the chance of a hidden agreement that lets tampering through.

The Go side is intentionally tiny (3 files, ~500 LOC) so an
auditor with no Erlang background can read it end-to-end in 30
minutes and know exactly what is being checked.

## Cross-check / regression test

```bash
make verifier-xcheck
```

Generates a signed-and-sealed audit log via the Erlang
implementation, feeds it to the Go verifier in all four happy-path
modes, then runs three tamper exercises (byte / wrong pubkey /
wrong HMAC). Asserts the right exit code for each — exit 0 from
the demo means all 7 scenarios matched expectation.

This is the canonical cross-language regression test. If either
side drifts on canonical-JSON encoding, hash chain semantics,
Ed25519 signing, or HMAC seal format, this target fails loud and
fast. Wire it into CI alongside the EUnit + ExUnit suites.

The same flow is also playable step-by-step in book Chapter 20.
