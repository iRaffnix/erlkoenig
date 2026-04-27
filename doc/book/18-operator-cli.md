# Chapter 18 — Operator CLI

`ek` is a single command-line tool for everyday operator work. Most
commands connect over Erlang distribution to the local node, run RPC
calls against public modules, and format the result as a table, JSON,
or plain text. A small local tier (`doctor`, `explain`, `dsl compile`)
does not need a running daemon, which makes it useful before first
start and inside CI.

The CLI is a convenience layer, not a separate API. Remote commands map
to the same Erlang modules that the system uses internally; local
commands read release artifacts such as the bundled Elixir tree and the
structured error catalog.

For a terse command reference intended for daily use, see
`docs/CLI.md`. This chapter keeps the operator narrative and examples.

## Installation

The CLI ships with the release. After `install.sh` runs, two files
are in place:

- `/opt/erlkoenig/bin/ek` — a small shell wrapper that
  finds the bundled `escript` and delegates to the script file.
- `/opt/erlkoenig/share/ek.escript` — the script itself.

For interactive use, add `/opt/erlkoenig/bin` to the operator's
`$PATH` or invoke the wrapper by absolute path:
`/opt/erlkoenig/bin/ek`.

## Connecting

The CLI joins the cluster as a hidden node, which means it doesn't
appear in `nodes()` and won't trigger any node-up handlers. Two
inputs control the connection:

- **Cookie file** — defaults to `/etc/erlkoenig/cookie`. Override
  with `--cookie-file <path>` or `ERLKOENIG_COOKIE_FILE=<path>`.
- **Target node** — defaults to `erlkoenig@<hostname>`. Override
  with `--node <name>` for cross-node operations later.

`doctor`, `explain`, and `dsl compile` skip distribution setup. They
can run on a build host or on a partially installed target even when
`erlkoenig.service` is not reachable.

## Output formats

Three formats are recognised through `--format` for commands that return
structured rows or key/value data:

- `table` (default) — human-readable columns
- `json`            — machine-readable
- `plain`           — tab-separated, suitable for shell pipelines

Pure status commands such as `node ping`, `dsl compile`, and
`admission snapshot` print plain status text.

## Subcommand catalogue

### Node

| Command                 | Effect                                            |
|-------------------------|---------------------------------------------------|
| `node ping`             | Liveness check, prints `pong` on success         |
| `node version`          | App version of the running erlkoenig             |
| `node health`           | Uptime in milliseconds + supervisor child count  |

`ek ping` is a short alias for `ek node ping`. `ek --version`, `ek -V`, and
`ek version` print the local CLI version without contacting the node.

### Local Diagnostics

| Command                        | Effect                                      |
|--------------------------------|---------------------------------------------|
| `doctor`                       | Host/install checks with catalog-backed codes |
| `explain <code>`               | Full description, action, evidence fields   |
| `explain --list`               | Short list of all known structured codes    |
| `explain --component <name>`   | Filter codes by component                   |

`doctor` checks the runtime binary, cookie file, socket directory,
cgroup v2, `nft`, and protocol-vector path. Failing or warning checks
emit an `EK_*` code that can be fed directly into `ek explain`.

### Stack Lifecycle

| Command        | Effect                                                |
|----------------|-------------------------------------------------------|
| `up <file>`    | Start a stack; accepts `.exs` or `.term`              |
| `down <file>`  | Stop containers declared in the stack file            |
| `down`         | Stop every running container on the target node       |

`up` is the operator-facing path. For `.exs` input it compiles the DSL
to a sibling `.term` using the bundled Elixir runtime, then loads the
term file. `.term` input is passed through directly.

### Config and DSL

| Command                         | Effect                                   |
|---------------------------------|------------------------------------------|
| `dsl compile <file.exs>`        | Compile to `<file>.term` beside source   |
| `dsl compile <file.exs> -o <out>` | Compile to an explicit term path       |
| `config validate <file.term>`   | Parse and validate a term file           |
| `config load <file.term>`       | Low-level load path                      |
| `config reload <file.term>`     | Low-level delta reload                   |

Use `config validate` for a validate-first deploy workflow. Use `up`
for normal operator work because it handles both DSL source and term
artifacts.

### Containers

| Command                       | Effect                                         |
|-------------------------------|------------------------------------------------|
| `ct list`                     | All running containers, table view             |
| `ct inspect <name>`           | Full state map for one container               |
| `ct stop <name>`              | Send the stop signal (SIGTERM, then SIGKILL)   |

The container name resolves against both the DSL `name:` field and
the internal id; either works.

`ek ps` is the Docker-familiar alias for `ek ct list`; `ek inspect
<name>` and `ek stop <name>` are aliases for the corresponding `ct`
commands. `ct inspect` appends a lifecycle timeline in table/plain
output and includes that timeline as a field in JSON output.

### Pods

| Command          | Effect                                               |
|------------------|------------------------------------------------------|
| `pod list`       | Active pod supervisors and non-terminal child count  |
| `pod list --all` | Include pods whose children are all stopped/failed   |

### Volumes

Volumes live in a UUID-keyed metadata store
(`erlkoenig_volume_store`). The CLI exposes the operator surface:

| Command                                  | Effect                                |
|------------------------------------------|---------------------------------------|
| `vol list`                               | Every registered volume               |
| `vol list --container <name>`            | Filter to one container               |
| `vol inspect <uuid|persist-name>`        | Full record (uuid, host_path, quota…) |
| `vol destroy <uuid> --yes`               | Remove metadata + on-disk directory   |
| `vol orphans`                            | UUID dirs without a metadata record   |
| `vol set-quota <uuid> <size>`            | Set or change XFS project quota       |

`<size>` accepts the same syntax as the DSL: `1G`, `500M`, integer
bytes. Setting `0` clears enforcement while keeping the project
binding (cheaper to raise again later).

### Quarantine

| Command                                          | Effect                              |
|--------------------------------------------------|-------------------------------------|
| `quarantine list`                                | Currently quarantined hashes        |
| `quarantine add <hash>`                          | Manually quarantine                 |
| `quarantine add <hash> --reason <reason>`        | Manually quarantine with a label    |
| `quarantine remove <hash>`                       | Lift a quarantine                   |

The hash is the SHA-256 hex string of the binary, as printed in the
`security.<prefix>.quarantined` AMQP event or via
`erlkoenig_sig:hash_file/1`.

### Admission

| Command                | Effect                                            |
|------------------------|---------------------------------------------------|
| `admission snapshot`   | In-flight, queued, and per-zone counts            |

## Command Groups At A Glance

```
ek node ping
ek node version
ek node health

ek doctor
ek explain EK_RUNTIME_HANDSHAKE_FAILED
ek explain --component audit

ek dsl compile stack.exs -o stack.term
ek config validate stack.term
ek up stack.exs
ek down stack.term

ek ps
ek ct inspect web-0-api
ek ct stop web-0-api
ek pod list
ek pod list --all

ek vol list
ek vol list --container web-0-api
ek vol inspect ek_vol_...
ek vol set-quota ek_vol_... 1G
ek vol orphans

ek quarantine list
ek quarantine add <sha256-hex> --reason operator_ban
ek quarantine remove <sha256-hex>

ek admission snapshot
```

## Hands-on: a live operator session

This transcript walks through what an operator typically runs during
incident response. The setup assumes a stack already loaded; if nothing
is running, start with `ek up examples/pg_demo.exs` first.

**1. Quick liveness check.**

```
$ ek node ping
pong

$ ek node version
0.9.0

$ ek node health
uptime_ms       7812403
supervisors     12
```

**2. What's running right now.**

```
$ ek ps
name           state    ip         zone  restart_count
-------------  -------  ---------  ----  -------------
pg-0-postgres  running  10.90.0.2  db    0
```

`ek ps` is an alias for `ek ct list`. The `restart_count` column is
the persistent_term-backed counter — surviving BEAM restarts and
pod-supervisor respawns.

**3. Drill into one container.**

```
$ ek ct inspect pg-0-postgres
state           running
ip              10.90.0.2
zone            db
os_pid          156329
restart_count   0
uid             70
gid             70
binary          /opt/erlkoenig/rt/demo/test-erlkoenig-echo_server
volumes         /data, /etc/postgresql, /scratch
```

For scripting, add `--format json`:

```
$ ek --format json ct inspect pg-0-postgres | jq '{state, os_pid, uid}'
{
  "state": "running",
  "os_pid": 156329,
  "uid": 70
}
```

**4. Volume inventory.**

```
$ ek vol list
uuid                     container      persist       lifecycle   host_path
-----------------------  -------------  ------------  ----------  -------------------------------------
ek_vol_35766831dfb3738d  pg-0-postgres  pg-data       persistent  /var/lib/erlkoenig/volumes/ek_vol_...
ek_vol_3b50a40729f97965  pg-0-postgres  pg-config     persistent  /var/lib/erlkoenig/volumes/ek_vol_...
ek_vol_b476d09fed8ad6a8  pg-0-postgres  pg-wal-stage  ephemeral   /var/lib/erlkoenig/volumes/ek_vol_...

$ ek vol inspect ek_vol_35766831dfb3738d
uuid         ek_vol_35766831dfb3738d
container    pg-0-postgres
persist      pg-data
host_path    /var/lib/erlkoenig/volumes/ek_vol_35766831dfb3738d
uid          70
gid          70
lifecycle    persistent
quota_bytes  10485760
project_id   10000
```

**5. Raise a quota on the fly.**

```
$ ek vol set-quota ek_vol_35766831dfb3738d 20M
quota set on ek_vol_35766831dfb3738d to 20M
```

No container restart, no remount — next write above the old 10 M cap
succeeds immediately.

**6. Clean up orphaned UUID directories.**

Sometimes a crash leaves the directory on disk without a DETS record
(or vice versa):

```
$ ek vol orphans
disk    ek_vol_abcdef...  /var/lib/erlkoenig/volumes/ek_vol_abcdef...
```

`ek vol destroy <uuid> --yes` removes both. If only the directory is
present (no metadata), a simple `rm -rf` on the host path is safe.

**7. Deal with a quarantined binary.**

```
$ ek quarantine list
hash                                                              reason               since
----------------------------------------------------------------  -------------------  --------------------
AB0C33F207D8588FEFC90DD5FDC7B2FB2B5554BAD983BEDC512D007480760513  {crashloop,5,60000}  2026-04-17T12:49:26Z

$ ek quarantine remove ab0c33f207d8588fefc90dd5fdc7b2fb2b5554bad983bedc512d007480760513
unquarantined AB0C33F207D8588FEFC90DD5FDC7B2FB2B5554BAD983BEDC512D007480760513
```

The hash is case-insensitive, 64 hex chars, always SHA-256. The
binary stays quarantined across BEAM restarts because it's held in
persistent_term — so manual `ek quarantine remove` is the only way
out once a binary is blacklisted.

**8. Admission gate.**

Under sustained load, the spawn-admission gate limits concurrent
container setup. A snapshot shows the backlog:

```
$ ek admission snapshot
in_flight     3
queue         0
queue_limit   100
max_host      10
per_zone      {db: 1, web: 2}
```

If `queue` creeps up and `in_flight` stays at `max_host`, the host is
saturated — new spawns are queueing, not failing. Tune via sys.config
keys `admission_max_host` / `admission_max_per_zone` (→ Chapter 16).

**9. Graceful shutdown of the stack.**

```
$ ek down ~/my_stack.exs
down: stopped 1/1 container(s)
```

Persistent volumes survive. Ephemeral ones are cleaned up on the
transition to `stopped` (see Chapter 8). Quarantines and ban-list
entries survive the shutdown; daemon restart clears the in-memory
mesh but not the quarantine.

## Everyday one-liners

```
# Local preflight without a running node
ek --format json doctor | jq '.[] | select(.status != "ok")'

# Explain every critical audit code
ek --format json explain --component audit \
  | jq '.[] | select(.severity == "critical")'

# Compile and validate before touching running state
ek dsl compile ~/my_stack.exs -o /tmp/my_stack.term
ek config validate /tmp/my_stack.term

# "How many containers are up" — for a monitoring script
ek --format plain ct list | wc -l

# Every container in a specific zone
ek --format json ct list | jq '.[] | select(.zone == "db")'

# Grep for a specific volume by persist name
ek vol list | awk '/pg-data/ {print $1}'
```

## Behaviour on error

Three classes of failure are surfaced cleanly:

- **Cookie / connection failures** print a one-line error pointing
  at the cookie path or target node.
- **Unknown commands** print the help-pointer.
- **Remote API mismatches** (CLI is newer than the deployed release
  and calls a function the running node doesn't have) surface as
  `remote call M:F/N is undef on <node> — release may be older
  than this CLI` rather than dumping an Erlang stack trace.

Genuine internal exceptions still print a full trace, because at
that point the operator wants the detail.

## Where this chapter doesn't go

The command-line escript is intentionally narrower than the interactive
Erlang shell helper module `ek`. The following operator tasks are not
part of the shipped one-shot CLI yet:

- **`fw` (firewall)** — needs a serialiser that renders the live
  nft state to text or JSON. The Erlang surface is there
  (`erlkoenig_nft_firewall`), only the formatter is missing.
- **`threat`** — needs a public API on `erlkoenig_threat_actor` /
  `_mesh` that returns a stable snapshot. Today the gen_statem
  state isn't designed for external read.
- **`events tail`** — long-running subscribe; needs a different
  signal-handling story than the one-shot RPC pattern.
- **`logs` / `top`** — interactive streaming views exist naturally in
  an attached Erlang shell, but the packaged `ek` escript currently
  keeps to one-shot commands.
- **`elf analyze`** — calling `erlkoenig_elf:parse/1` on an
  arbitrary file is straightforward, but the printable rendering
  needs design work.
- **`sig sign` / `pki`** — Build-pipeline integration usually wants
  something more scriptable than an interactive CLI.

Each of these is a small extension of the same dispatch table once
the underlying API is stable.
