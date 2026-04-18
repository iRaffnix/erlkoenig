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

A trust root is an X.509 certificate in PEM form. The paths are
listed explicitly in sys.config under `trust_roots` (default: empty
list). The runtime loads all listed certificates at boot into an
in-memory pool. Signature
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

The failure modes are all distinct atoms — `sha256_mismatch`,
`signature_invalid`, `chain_too_short`, `untrusted_root`,
`sig_not_found` — so operators can tell at a glance what went wrong.
Certificate expiry is caught by `pkix_path_validation` and surfaces
as part of the chain validation error.

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

## Hands-on: sign, verify, tamper, reject

This walkthrough takes a binary through the full signature lifecycle.
Requires `openssl` on the host for key generation.

**1. Generate a signing key and self-signed cert.**

```bash
mkdir -p /tmp/pki && cd /tmp/pki

# Ed25519 private key
openssl genpkey -algorithm ed25519 -out signer.key

# Self-signed cert (production: this would be issued by a CA)
openssl req -new -x509 -key signer.key -out signer.pem \
    -days 365 -subj "/CN=erlkoenig-build-signer/O=example"

# Inspect
openssl x509 -in signer.pem -noout -text | head -15
```

**2. Sign a binary.**

```bash
cp /opt/erlkoenig/rt/demo/test-erlkoenig-echo_server /tmp/pki/demo
erlkoenig eval '
  erlkoenig_sig:sign(
    "/tmp/pki/demo",
    "/tmp/pki/signer.pem",
    "/tmp/pki/signer.key",
    #{git_sha => <<"abcdef0123456789abcdef0123456789abcdef01">>}
  ).'
# Writes /tmp/pki/demo.sig
ls -la /tmp/pki/demo.sig
```

The `.sig` file is compact binary — cert chain (PEM), signature
(base64), and the signed payload (SHA-256 of the binary + git SHA +
timestamp + signer CN).

**3. Configure trust.** Edit the runtime config to trust this root
certificate:

```bash
mkdir -p /etc/erlkoenig/ca
cp /tmp/pki/signer.pem /etc/erlkoenig/ca/
```

Update `sys.config` to enable enforcement:

```erlang
{erlkoenig, [
    ...,
    {signature, #{
        mode            => on,
        trust_roots     => ["/etc/erlkoenig/ca/signer.pem"],
        min_chain_depth => 2
    }}
]}.
```

Restart the daemon for `sys.config` changes to take effect.

**4. Verify the signature directly (no daemon needed).**

```bash
erlkoenig eval '
  case erlkoenig_sig:verify(
    "/tmp/pki/demo",
    "/tmp/pki/demo.sig") of
    {ok, Meta} ->
      io:format("VERIFIED~n"
                "  signer:    ~s~n"
                "  git_sha:   ~s~n"
                "  sha256:    ~s~n",
        [maps:get(signer, Meta),
         maps:get(git_sha, Meta),
         binary:encode_hex(maps:get(sha256, Meta))]);
    {error, Reason} ->
      io:format("REJECTED: ~p~n", [Reason])
  end.'
```

Output (on success):

    VERIFIED
      signer:    erlkoenig-build-signer
      git_sha:   abcdef0123456789abcdef0123456789abcdef01
      sha256:    AB0C33F207D8588F...

**5. Spawn a container with the signed binary.** With `mode => on`
the runtime rejects any spawn whose binary lacks a valid signature.
A correctly-signed binary spawns normally:

```bash
cat > /tmp/pki/stack.exs << 'EOF'
defmodule SignedStack do
  use Erlkoenig.Stack
  host do
    ipvlan "s", parent: {:dummy, "ek_s"}, subnet: {10, 111, 0, 0, 24}
  end
  pod "p", strategy: :one_for_one do
    container "app", binary: "/tmp/pki/demo", args: ["9000"],
      signature: :required,
      zone: "s", replicas: 1, restart: :permanent
  end
end
EOF
ek dsl compile /tmp/pki/stack.exs -o /tmp/pki/stack.term
ek up /tmp/pki/stack.term
ek ps       # app-0-app running
```

An AMQP event `security.app-0-app.verified` fires on spawn.

**6. Tamper, observe rejection.**

```bash
ek down /tmp/pki/stack.term
# Modify one byte — breaks the SHA-256 in the signature
printf '\x00' | dd of=/tmp/pki/demo bs=1 count=1 conv=notrunc seek=100
ek up /tmp/pki/stack.term
ek ps   # empty — container refused to start
```

The daemon logs a rejection; the AMQP bus produces:

    security.app-0-app.rejected   { reason: sha256_mismatch,
                                     binary: "/tmp/pki/demo" }

`ek ct inspect` on the failed container shows
`error_reason: sha256_mismatch`.

**7. Delete the `.sig` file, see the next failure mode.**

```bash
rm /tmp/pki/demo.sig
ek up /tmp/pki/stack.term
# error_reason: sig_not_found
```

**8. Mode switches for migration.** On systems that don't yet have
all binaries signed, `mode => warn` logs the outcome without
enforcing — useful to observe the blast radius before flipping to
`on`:

```erlang
{signature, #{mode => warn, ...}}
```

Every unsigned or mismatched binary produces a `security.*.rejected`
event, but the spawn goes through. Once the warnings stop, flip to
`on` and the enforcement is live.
