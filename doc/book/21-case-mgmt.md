## Chapter 21 — Full-Stack Use-Case: case_mgmt

This chapter takes the capability framework (→ Chapter 19) and the
audit verifier (→ Chapter 20) and assembles them into a real
workload: a small task-tracker agent that talks to Postgres over a
bind-mounted Unix socket and writes a tamper-evident audit trail.

You'll spawn a Go binary that lives inside an erlkoenig container,
declares two service capabilities (`:postgres.local` and
`:journal.local`), and exposes a tiny HTTP API. Every mutation
becomes a tamper-evident audit event that the external Go verifier
can re-check offline. ~25 minutes from scratch to "I just proved
end-to-end integrity of a real workload with cryptography".

> **Scope honesty.** The full reference deployment also imagines
> per-tenant SQLCipher under a `:tenant.local` capability, and a
> `:keystore.local` key broker that audit-logs every release.
> Those are deferred (see the
> `project_per_tenant_crypto` design memo). This chapter ships
> the compliance-relevant core (audit chain + structured workload
> data) — the per-tenant evolution plugs in later.

## What you'll prove

- A Go binary in a container can use Postgres via Unix socket with
  **zero password and zero TLS** — peer auth + the bind-mount IS
  the access grant.
- Each mutation writes to `:journal.local` → audit chain.
- The chain is **independently verifiable offline** by the Go
  verifier from chapter 20. An auditor with the public key and the
  HMAC key can prove no one tampered with the workload's history.

---

## Step 0 — Build

```bash
make erl                                 # erlang side
make verifier                            # the offline Go verifier
cd examples/agents/case_mgmt && \
  CGO_ENABLED=0 go build -ldflags="-s -w" -o case_mgmt .
```

Three artefacts:
- `_build/default/...`    — erlkoenig BEAMs
- `dist/audit-verifier`   — 2.4 MB customer-side binary (chapter 20)
- `examples/agents/case_mgmt/case_mgmt` — 10 MB workload binary (this chapter)

## Step 1 — Postgres on the host

The walking skeleton needs Postgres listening on the same socket
directory the capability framework bind-mounts. On a Debian 13 host:

```bash
apt-get install -y postgresql postgresql-contrib

# Postgres listens on /run/erlkoenig/.s.PGSQL.5432 in addition to
# its default /var/run/postgresql.
sed -i "s|^#\\?unix_socket_directories.*|unix_socket_directories = '/var/run/postgresql,/run/erlkoenig'|" \
    /etc/postgresql/17/main/postgresql.conf

mkdir -p /run/erlkoenig
chmod 0777 /run/erlkoenig         # walking-skeleton convenience
                                  # production: per-service group
```

Peer auth + ident map in `/etc/postgresql/17/main/pg_hba.conf`:

```
local   all   postgres                          peer
local   all   all                               peer map=erlkoenig_caps
host    all   all       127.0.0.1/32            scram-sha-256
host    all   all       ::1/128                 scram-sha-256
```

And `pg_ident.conf` — for the walking skeleton, ANY system user
that reaches the socket maps to `case_mgmt`:

```
# MAPNAME       SYSTEM-USERNAME       PG-USERNAME
erlkoenig_caps  /^.*$                 case_mgmt
```

> **Production split.** Per-container role isolation (each container
> runs under a deterministic uid that maps to its own role) is the
> next step on the roadmap. For walking skeleton, one role.

Restart + create the role + db + schema:

```bash
systemctl restart postgresql@17-main

sudo -u postgres psql <<'SQL'
CREATE ROLE case_mgmt LOGIN;
CREATE DATABASE cases OWNER case_mgmt;
SQL

# Apply the full schema (idempotent: drops + recreates).
sudo -u postgres psql -d cases -f examples/agents/case_mgmt/schema.sql
```

The schema lives in the repo at `examples/agents/case_mgmt/schema.sql`:
five tables (`users`, `tasks`, `task_notes`, `deadlines`,
`time_entries`) with the indexes the agent's queries need.

Smoke test from the host (no container yet):

```bash
sudo -u postgres psql -h /run/erlkoenig -U case_mgmt -d cases \
    -c "INSERT INTO tasks (title, description) VALUES ('smoke', 'host-side ping') RETURNING id;"
```

If you see `INSERT 0 1`, peer auth is working.

## Step 2 — Run the workload directly (no container)

Before wrapping in a container, sanity-check the binary against the
running Postgres:

```bash
PGHOST=/run/erlkoenig ./examples/agents/case_mgmt/case_mgmt &
sleep 1

curl -s localhost:8080/healthz
# → ok

curl -s -X POST localhost:8080/tasks \
    -d '{"title":"Investigate flaky test","description":"reproducing locally first"}'
# → {"id":2,"title":"Investigate flaky test","description":"..."}

curl -s -X POST localhost:8080/tasks/2/notes \
    -d '{"body":"reproduced on first try, opening bug"}'
# → {"id":1}

curl -s localhost:8080/tasks/2 | jq .
# → full task + notes + deadlines + time_entries + effort summary
```

The binary uses **only `PGHOST`** to find Postgres. No password,
no host name, no port lookup — libpq sees the directory and
discovers `.s.PGSQL.5432` inside.

## Step 3 — The DSL stack file

`examples/case_mgmt_stack.exs` declares a one-container pod
with the three capabilities the workload depends on:

```elixir
container "agent",
  binary: "/opt/erlkoenig/rt/demo/case_mgmt",
  zone: "ops",
  replicas: 1,
  restart: :permanent,
  limits: %{memory: 256_000_000, pids: 128} do

  requires :"postgres.local"
  requires :"journal.local"
  requires :"dns.local"

  publish interval: 2000 do
    metric :memory
    metric :cpu
    metric :pids
  end

  stream retention: {30, :days} do
    channel :stdout
    channel :stderr
  end

  nft do
    input policy: :drop do
      nft_rule :accept, ct_state: [:established, :related]
      nft_rule :accept, ip_protocol: :icmp
      nft_rule :accept, tcp_dport: 8080
    end
    output policy: :drop do
      nft_rule :accept, ct_state: [:established, :related]
      nft_rule :accept, ip_protocol: :icmp
      nft_rule :accept, ip_daddr: {10, 70, 0, 1}
    end
  end
end
```

The three `requires` lines are the whole grant surface:

| Declaration              | What gets injected                                                                 |
|--------------------------|------------------------------------------------------------------------------------|
| `requires :"postgres.local"` | bind-mount `/run/erlkoenig/`, env `PGHOST=/run/erlkoenig`                       |
| `requires :"journal.local"`  | bind-mount (same dir, dedup), env `JOURNAL_LOCAL_SOCK=/run/erlkoenig/journal.sock` |
| `requires :"dns.local"`      | (informational; runtime configures `/etc/resolv.conf` already)                  |

The host firewall block in the file mirrors the runtime services
explicitly — operator owns it (no magic injection, → Chapter 19).

## Step 4 — Live spawn + curl + verify

The repo ships `tests/integration/45_case_mgmt.escript` which
boots erlkoenig, spawns the container, hits the API, and verifies
the chain. From the project root **as root**:

```bash
sudo ./tests/integration/45_case_mgmt.escript
```

Expected output (~10 s):

```
=== Test 45: case_mgmt walking skeleton ===

[OK  ] spawn case_mgmt container with postgres.local + journal.local
       container os_pid=405389 ip=10.0.0.235
[OK  ] container's /healthz returns ok
[OK  ] POST /tasks creates a task in Postgres + writes journal entry
       response: {"id":3,"title":"Smoke test ...","description":"end-to-end probe..."}
[OK  ] POST a note + GET /tasks/:id sees both fields
       GET response: {...,"notes":[{"body":"first triage note...",...}]}
[OK  ] audit chain captured the journal entries  (chain has 2 events)

    audit log kept at: /tmp/erlkoenig_audit_test_45_<TAG>.jsonl

=== Test 45 passed ===
```

## Step 5 — Re-verify the chain offline

Take the audit-log path printed at the end and feed it to the Go
verifier:

```bash
dist/audit-verifier verify-chain /tmp/erlkoenig_audit_test_45_<TAG>.jsonl
# → ok: 2 event(s), chain head <hex>
# → exit=0
```

That single command is the **compliance proof loop**: an external
binary that knows nothing about the runtime can re-prove every
mutation the workload made was recorded faithfully and
non-tampered. Hand the binary + the public key + the audit log to
your auditor; they get the same result.

## What you didn't have to do

- No password management for Postgres
- No TLS certificate provisioning between container and DB
- No SCRAM-SHA-256 secret rotation
- No connection-string manifests in the container
- No `pg_audit` setup (the chain captures business events; query-
  level audit is a separate concern)

The bind-mount of `/run/erlkoenig/` is the access grant. peer-auth
is the cred. The capability declaration is the contract.

## What this chapter does NOT cover

- **Per-tenant cryptographic isolation** — see the
  `project_per_tenant_crypto` design memo; combines
  `:tenant.local` (encrypted SQLite per tenant) with
  `:keystore.local` (key broker that audit-logs every release).
- **AI inference** — the `:inference.local` walking skeleton
  needs a GPU + a multi-GB model file. Plug it into the same DSL
  surface when it lands.
- **Per-container role isolation** — today: one role for the
  whole container. Production needs per-uid mapping.
- **Multi-replica scaling** — `replicas: 1` for now; safe scale-out
  needs the per-container role isolation above.
