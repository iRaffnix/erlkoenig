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

The showcase path also ships a second Go binary,
`deadline_worker`, which polls the case API and writes its own
journal events. The one-shot integration test focuses on the
`case_mgmt` API path; the long-running showcase pod starts both
containers.

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
make agents-build                        # both Go agents
make verifier                            # the offline Go verifier
```

Three artefacts:
- `_build/default/...`    — erlkoenig BEAMs
- `dist/audit-verifier`   — 2.4 MB customer-side binary (chapter 20)
- `examples/showcase/bin/case_mgmt` — HTTP task-tracker workload
- `examples/showcase/bin/deadline_worker` — deadline polling worker

`make agents-build` is the source of truth for the Go build. It
compiles `examples/agents/case_mgmt` and
`examples/agents/deadline_worker` into `examples/showcase/bin/`.

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
PGHOST=/run/erlkoenig ./examples/showcase/bin/case_mgmt &
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

`examples/showcase/case_mgmt_stack.exs` is the declarative showcase
stack file. It declares the host firewall, the `ops` zone, and the
`case_mgmt` pod with the service capabilities the API container
depends on:

```elixir
container "agent",
  binary: "/opt/erlkoenig/rt/demo/case_mgmt",
  zone: "ops",
  restart: :permanent,
  limits: %{memory: 256_000_000, pids: 128} do

  requires :"postgres.local"
  requires :"journal.local"
  requires :"dns.local"
  requires :"dns.allowlist",
    hosts: [
      "*.postgres.internal",
      "audit.erlkoenig.internal"
    ]

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

Those `requires` lines are the whole grant surface:

| Declaration              | What gets injected                                                                 |
|--------------------------|------------------------------------------------------------------------------------|
| `requires :"postgres.local"` | bind-mount `/run/erlkoenig/`, env `PGHOST=/run/erlkoenig`                       |
| `requires :"journal.local"`  | bind-mount (same dir, dedup), env `JOURNAL_LOCAL_SOCK=/run/erlkoenig/journal.sock` |
| `requires :"dns.local"`      | (informational; runtime configures `/etc/resolv.conf` already)                  |
| `requires :"dns.allowlist"`  | per-source DNS allowlist; denied names become audited NXDOMAINs                |

The host firewall block in the file mirrors the runtime services
explicitly — operator owns it (no magic injection, → Chapter 19).

The long-running showcase runner,
`tests/integration/showcase_case_mgmt.escript`, uses the deployed
runtime paths directly and starts two containers:

| Container | Runtime binary | Purpose |
|-----------|----------------|---------|
| `case_mgmt-0-agent` | `/opt/erlkoenig/rt/demo/case_mgmt` | HTTP API on `10.0.0.210:8080` |
| `case_mgmt-0-worker` | `/opt/erlkoenig/rt/demo/deadline_worker` | polls upcoming deadlines and writes journal events |

## Step 4 — Deploy the showcase files

`make showcase` is the repo-supported deployment path. By default it
targets `erlkoenig-2__root` and copies both built agents to
`/opt/erlkoenig/rt/demo/` on that host:

```bash
make showcase
```

The target:

- runs `make agents-build`
- copies `case_mgmt` and `deadline_worker` to
  `/opt/erlkoenig/rt/demo/`
- copies `schema.sql` and `seed.sql` to the host
- resets and seeds the `cases` database
- copies `tests/integration/showcase_case_mgmt.escript` to the host

At the end it prints the two operator entry points:

```bash
ssh erlkoenig-2__root /root/erlkoenig/tests/integration/showcase_case_mgmt.escript
ssh erlkoenig-2__root /root/erlkoenig/tests/integration/45_case_mgmt.escript
```

## Step 5 — One-shot live spawn + curl + verify

The repo ships `tests/integration/45_case_mgmt.escript` which
boots erlkoenig, spawns the `case_mgmt` container, hits the API,
and verifies the chain. On a prepared host **as root**:

```bash
ssh erlkoenig-2__root /root/erlkoenig/tests/integration/45_case_mgmt.escript
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

For local development on the target host, the same test can also be
run directly from the project root:

```bash
sudo ./tests/integration/45_case_mgmt.escript
```

## Step 6 — Run the long-lived showcase pod

For an operator-facing demo, start the long-running runner that
`make showcase` deployed:

```bash
ssh erlkoenig-2__root /root/erlkoenig/tests/integration/showcase_case_mgmt.escript
```

It starts both deployed binaries:

```text
case_mgmt:        http://10.0.0.210:8080
deadline_worker:  polls case_mgmt every 30s
audit log:        /var/log/erlkoenig/case_mgmt_audit.jsonl
```

Try the API while the runner is active:

```bash
ssh erlkoenig-2__root 'curl -s http://10.0.0.210:8080/tasks | jq .'
ssh erlkoenig-2__root 'curl -s http://10.0.0.210:8080/deadlines/upcoming?days=30 | jq .'
```

## Step 7 — Re-verify the chain offline

Take the audit-log path printed at the end and feed it to the Go
verifier:

```bash
dist/audit-verifier verify-chain /tmp/erlkoenig_audit_test_45_<TAG>.jsonl
# → ok: 2 event(s), chain head <hex>
# → exit=0
```

For the long-running showcase log, the Makefile has a wrapper:

```bash
make showcase-verify
```

That target pulls `/var/log/erlkoenig/case_mgmt_audit.jsonl` from
the showcase host and verifies it with `dist/audit-verifier`.

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
- **Multi-instance scaling** — one API container and one worker
  container for now; safe scale-out needs the per-container role
  isolation above.
