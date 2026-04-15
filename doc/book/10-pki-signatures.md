# Chapter 10 — PKI & Signatures

erlkoenig can refuse to spawn a container whose binary lacks a valid
Ed25519 signature from a trusted chain. This is the deployment-time
integrity check: what arrived on disk has to match what a trusted
signer put there. The chain is verified against a configured set of
trust roots; anything that fails to validate is rejected before the
process ever starts.

## Why binary signatures

A signed binary answers one question: did the code running inside
the container come from a source I trust? The check runs on every
spawn, so tampering after deployment (whether malicious or
accidental) takes effect only if the tamperer can also steal the
signing key. In practice this closes two attack paths: host-side
compromise that replaces the binary before spawn, and supply-chain
injection upstream of the release pipeline.

## Trust roots

A trust root is an X.509 certificate in PEM form, placed under
`/etc/erlkoenig/ca/` (or wherever sys.config points). The runtime
loads all of them at boot into an in-memory pool. Signature
verification uses `public_key:pkix_path_validation/3` to chain the
signer's certificate back to a root in the pool — standard X.509
semantics, including expiry and revocation checks.

A chain depth of at least two is the enforced minimum
(`min_chain_depth`): root → signing cert. Deeper chains (root →
sub-CA → signing cert) work the same way. Chains that terminate too
short fail with `chain_too_short`.

## The signature file

A signed binary ships with a companion `.sig` file next to it. The
format is compact binary:

```
Version:8 | Algorithm:8 | SHA-256(binary):32 | GitSHA:20 |
Timestamp:64 | CN-length:16 | CN:variable | Signature | Cert chain (DER)
```

Version and algorithm are fixed at the moment — version 1, Ed25519.
The SHA-256 ties the signature to the exact byte contents of the
binary. The Git SHA and timestamp help operators correlate what's
deployed with what's in version control. Everything after that is
cryptographic.

## Verification at spawn time

The check runs in the `creating` state of the container state
machine, before any namespaces are set up. `erlkoenig_sig:verify/2`
reads the `.sig` file, checks the hash against the binary on disk,
verifies the Ed25519 signature against the signer certificate, and
validates the certificate chain against the trust pool. Any failure
returns `{error, Reason}` and the container transitions to `failed`
with the reason recorded for inspection.

The failure modes are all distinct atoms — `hash_mismatch`,
`signature_invalid`, `chain_too_short`, `untrusted_root`,
`cert_expired`, `sig_file_missing` — so operators can tell at a
glance what went wrong.

## Operation modes

`sys.config` exposes three modes in the `signature` block:

```erlang
{signature, #{
    mode            => on,          %% on | warn | off
    trust_roots     => ["/etc/erlkoenig/ca/root.pem"],
    min_chain_depth => 2
}}
```

- **`on`** — reject unsigned or invalid binaries. Production default
  once signing is in place.
- **`warn`** — log the verification result but spawn regardless.
  Useful during migration to signed binaries.
- **`off`** — skip verification entirely. The factory default, so
  nothing breaks for users who haven't set up PKI.

`trust_roots` is a list of PEM file paths. An empty list combined
with `mode: on` is a misconfiguration and fails at boot.

## Signing workflow

`erlkoenig_sig:sign/4` is the canonical way to produce a `.sig`:

```erlang
erlkoenig_sig:sign(
    "/opt/app/server",                            % binary path
    "/etc/signing/signer.pem",                    % cert chain
    "/etc/signing/signer.key",                    % private key
    #{git_sha => <<"0a1b2c3d4e...">>}             % metadata
).
```

Typical integration: the CI pipeline builds the binary, signs it
with the build-signing key, and publishes both the binary and its
`.sig` to the artifact store. Deployment copies both to the target
host; the runtime does the rest.

Audit trails land on `security.<name>.verified` and
`security.<name>.rejected` routing keys (→ Chapter 9), so every
verification outcome is observable centrally.
