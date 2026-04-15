# Chapter 18 — Operator CLI

`ek` is a single command-line tool for everyday operator
work against a running erlkoenig node. It connects over Erlang
distribution to the local node, runs RPC calls against the public
modules, and formats the result as a table, JSON, or plain text.
Every operation that this chapter lists is also available
programmatically via the same modules — the CLI is a convenience
layer, not a separate API.

## Installation

The CLI ships with the release. After `install.sh` runs, two files
are in place:

- `/opt/erlkoenig/bin/ek` — a small shell wrapper that
  finds the bundled `escript` and delegates to the script file.
- `/opt/erlkoenig/share/ek.escript` — the script itself.

The wrapper is on the default `$PATH` for the erlkoenig service
account; for interactive use, add `/opt/erlkoenig/bin` to the
operator's `$PATH` or invoke by absolute path.

## Connecting

The CLI joins the cluster as a hidden node, which means it doesn't
appear in `nodes()` and won't trigger any node-up handlers. Two
inputs control the connection:

- **Cookie file** — defaults to `/etc/erlkoenig/cookie`. Override
  with `--cookie-file <path>` or `ERLKOENIG_COOKIE_FILE=<path>`.
- **Target node** — defaults to `erlkoenig@<hostname>`. Override
  with `--node <name>` for cross-node operations later.

## Output formats

Three formats are recognised through `--format`:

- `table` (default) — human-readable columns
- `json`            — machine-readable
- `plain`           — tab-separated, suitable for shell pipelines

The format flag is global: it works on every subcommand.

## Subcommand catalogue

### Node

| Command                 | Effect                                            |
|-------------------------|---------------------------------------------------|
| `node ping`             | Liveness check, prints `pong` on success         |
| `node version`          | App version of the running erlkoenig             |
| `node health`           | Uptime in milliseconds + supervisor child count  |

### Containers

| Command                       | Effect                                         |
|-------------------------------|------------------------------------------------|
| `ct list`                     | All running containers, table view             |
| `ct inspect <name>`           | Full state map for one container               |
| `ct stop <name>`              | Send the stop signal (SIGTERM, then SIGKILL)   |

The container name resolves against both the DSL `name:` field and
the internal id; either works.

### Pods

| Command   | Effect                                                |
|-----------|-------------------------------------------------------|
| `pod list`| All pod supervisors and their pids                    |

### Volumes

Volumes live in a UUID-keyed metadata store
(`erlkoenig_volume_store`). The CLI exposes the operator surface:

| Command                                  | Effect                                |
|------------------------------------------|---------------------------------------|
| `vol list`                               | Every registered volume               |
| `vol list --container <name>`            | Filter to one container               |
| `vol inspect <uuid|persist-name>`        | Full record (uuid, host_path, quota…) |
| `vol destroy <uuid>`                     | Remove metadata + on-disk directory   |
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

## Examples

```
# Quick liveness check
ek node ping

# How many containers are up
ek ct list

# JSON for a script that pipes through jq
ek --format json vol list | jq '.[].host_path'

# Diagnose a misbehaving container
ek ct inspect web-0-api

# Lift a quarantine after the underlying issue is fixed
ek quarantine remove 0a1b2c3d4e5f6789

# Find leftover volume directories
ek vol orphans
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

The CLI is intentionally narrow today. The following operator tasks
are deliberately out of MVP scope:

- **`fw` (firewall)** — needs a serialiser that renders the live
  nft state to text or JSON. The Erlang surface is there
  (`erlkoenig_nft_firewall`), only the formatter is missing.
- **`threat`** — needs a public API on `erlkoenig_threat_actor` /
  `_mesh` that returns a stable snapshot. Today the gen_statem
  state isn't designed for external read.
- **`events tail`** — long-running subscribe; needs a different
  signal-handling story than the one-shot RPC pattern.
- **`logs`** — stream consumer; same.
- **`elf analyze`** — calling `erlkoenig_elf:parse/1` on an
  arbitrary file is straightforward, but the printable rendering
  needs design work.
- **`sig sign`** — Build-pipeline integration usually wants
  something more scriptable than an interactive CLI.

Each of these is a small extension of the same dispatch table once
the underlying API is stable.
