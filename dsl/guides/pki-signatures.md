# PKI & Binary Signatures

erlkoenig supports cryptographic verification of container binaries.
Before a container starts, the runtime can verify that the binary was
signed by a trusted authority — preventing tampered or unauthorized
code from executing.

## How It Works

```
Build Pipeline                        Runtime
─────────────                         ───────

1. Build binary                    4. Container start
   /opt/myapp/server                  erlkoenig_ct:creating
       │                                  │
2. Sign with Ed25519                 5. maybe_verify_signature
   erlkoenig sign server               │
   --cert signing.pem                   ├── Read .sig file
   --key signing.key                    ├── Verify Ed25519 signature
       │                                ├── Check SHA-256 hash
3. Deploy binary + .sig               ├── Validate cert chain
   server + server.sig                 │   against trust store
                                        │
                                     6. mode = on  → reject if invalid
                                        mode = warn → log and continue
                                        mode = off  → skip verification
```

## Certificate Chain

erlkoenig uses a standard X.509 PKI hierarchy:

```
Root CA (self-signed, in trust store)
  └── Sub-CA (signed by Root)
        └── Signing Cert (signs binaries)
```

The trust store is configured in `sys.config`:

```erlang
{signature, #{
    mode => on,                                    %% on | warn | off
    trust_roots => ["/etc/erlkoenig/ca/root.pem"], %% trusted root CAs
    min_chain_depth => 2                           %% minimum chain length
}}
```

## .sig File Format

The signature file is PEM-encoded with a custom envelope:

```
-----BEGIN ERLKOENIG SIGNATURE-----
<base64: PayloadLen:32 | Payload | Ed25519-Signature>
-----END ERLKOENIG SIGNATURE-----
-----BEGIN CERTIFICATE-----
<signing certificate>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate CA>
-----END CERTIFICATE-----
```

### Signature Payload (v1)

| Field | Size | Description |
|-------|------|-------------|
| Version | 1 byte | Always `1` |
| Algorithm | 1 byte | `1` = Ed25519 |
| SHA-256 | 32 bytes | Hash of the binary |
| Git SHA | 20 bytes | Git commit (zero-padded if absent) |
| Timestamp | 8 bytes | Unix seconds (big-endian) |
| Signer CN Length | 2 bytes | Length of signer common name |
| Signer CN | variable | UTF-8 encoded CN from signing cert |

## CLI Usage

### Create PKI (development/testing)

```bash
# 1. Create Root CA
erlkoenig pki create-root-ca \
  --cn "Erlkoenig Root CA" \
  --out ca/root.pem \
  --key-out ca/root.key

# 2. Create Sub-CA
erlkoenig pki create-sub-ca \
  --cn "Erlkoenig Pipeline CA" \
  --ca ca/root.pem \
  --ca-key ca/root.key \
  --out ca/sub-ca.pem \
  --key-out ca/sub-ca.key

# 3. Create Signing Certificate
erlkoenig pki create-signer \
  --cn "ci-pipeline" \
  --ca ca/sub-ca.pem \
  --ca-key ca/sub-ca.key \
  --out ca/signing.pem \
  --key-out ca/signing.key
```

### Sign a Binary

```bash
erlkoenig sign /opt/myapp/server \
  --cert ca/signing.pem \
  --key ca/signing.key

# Creates: /opt/myapp/server.sig
```

### Verify a Binary

```bash
erlkoenig verify /opt/myapp/server

# Output:
#   Signature valid
#   Signer:    ci-pipeline
#   SHA-256:   a1b2c3d4...
#   Git SHA:   abcdef01...
#   Signed at: 2026-04-05T12:00:00Z
#   Chain:     2 certificates
```

## Erlang API

### Sign

```erlang
{ok, SigData} = erlkoenig_sig:sign(
    "/opt/myapp/server",
    "/etc/erlkoenig/ca/signing.pem",
    "/etc/erlkoenig/ca/signing.key",
    #{git_sha => <<"abcdef0123456789...">>}
).
file:write_file("/opt/myapp/server.sig", SigData).
```

### Verify

```erlang
{ok, Meta} = erlkoenig_sig:verify("/opt/myapp/server", "/opt/myapp/server.sig").
%% Meta = #{
%%     signer_cn => <<"ci-pipeline">>,
%%     sha256 => <<...>>,
%%     git_sha => <<"abcdef01...">>,
%%     timestamp => 1712300000,
%%     chain => [LeafDer, SubCaDer]
%% }
```

### Chain Validation

```erlang
%% Verify certificate chain against trust store
ok = erlkoenig_pki:verify_chain([SigningCertDer, SubCaDer]).

%% Check current mode
on = erlkoenig_pki:mode().

%% Reload trust store after config change
ok = erlkoenig_pki:reload().
```

## Verification Modes

| Mode | Invalid Signature | No .sig File |
|------|-------------------|--------------|
| `on` | Container rejected | Container rejected |
| `warn` | Log warning, start anyway | Log info, start anyway |
| `off` | Skip verification | Skip verification |

## Security Properties

- **Ed25519**: 128-bit security, no padding oracle attacks, deterministic signatures
- **Chain validation**: signing cert must chain to a trusted root via intermediate CAs
- **Minimum depth**: `min_chain_depth => 2` prevents direct root-signing (requires at least Root → Sub-CA → Signer)
- **Tamper detection**: SHA-256 hash of the binary is embedded in the signed payload — any modification invalidates the signature
- **Git traceability**: optional git SHA links the signed binary to a specific commit
- **Audit trail**: all verification results (pass/fail) are logged to the audit log

## Integration with Container Lifecycle

Verification happens in the `creating` state, **before** the SPAWN
command is sent to the C runtime. If verification fails in `on` mode,
the container transitions directly to `failed` state — the binary
never executes.

```
creating
  │
  ├── maybe_verify_signature(Data)
  │     ├── mode = off  → skip
  │     ├── mode = warn → verify, log result, continue
  │     └── mode = on   → verify, reject if invalid
  │
  ├── (if ok) creating_send_spawn(Data)
  │
  └── (if rejected) → failed state
```
