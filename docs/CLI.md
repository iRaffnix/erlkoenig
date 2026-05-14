# ek CLI Reference

`ek` is the operator command line for erlkoenig. It is shipped with the
release as `/opt/erlkoenig/bin/ek` plus the escript at
`/opt/erlkoenig/share/ek.escript`.

The examples below use `ek` for readability. If `/opt/erlkoenig/bin` is not
in the current shell's `PATH`, either add it or invoke
`/opt/erlkoenig/bin/ek` directly.

Most commands connect to the running node over Erlang distribution. Local
commands run without a daemon and are safe for preflight checks, CI, and
partially installed hosts.

## Global Options

```sh
ek [global-options] <area> <command> [args...]
```

| Option | Meaning |
|--------|---------|
| `--node <name>` | Target node. Default: `erlkoenig@<hostname>` |
| `--cookie-file <path>` | Cookie path. Default: `ERLKOENIG_COOKIE_FILE`, `/etc/erlkoenig/cookie`, then `~/.config/erlkoenig/cookie` |
| `--format table` | Human table output. Default |
| `--format json` | JSON output for tools |
| `--format plain` | Tab-separated output for shell pipelines |
| `--limit <n>` | Limit rows for commands backed by event/history buffers |

The `--key=value` form is also accepted for global options.

Formatting applies to commands that return structured rows or key/value data.
Pure status commands such as `node ping`, `dsl compile`, and
`admission snapshot` print plain status text.

## Stability

The CLI is an operator-facing public contract. Compatible changes are
additive: new commands, new flags, and new JSON fields are allowed.
Renaming or removing existing commands, flags, JSON fields, or field types is
a breaking change. The full JSON shape rules are in
[JSON Output Contract](#json-output-contract) below.

Stable exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime, remote, validation, or guarded destructive-operation error |
| `2` | Usage error or invalid arguments |
| `3` | Requested resource not found |

Expected operator errors start with `error:`. Erlang stack traces are bugs or
debug output, not normal CLI UX.

Deprecations warn for at least two minor releases before removal. Prefer
adding a replacement command or flag first, keeping the old name as an alias,
and removing only in a major version.

Sibling contracts follow the same rule: AMQP event payload field names and
types (`docs/AMQP_EVENTS.md`), wire protocol v1, and structured `EK_*` error
identifiers are stable operator contracts.

## Local Commands

These commands do not start Erlang distribution and do not need
`erlkoenig.service` to be reachable.

### `ek doctor`

Runs local host and install diagnostics:

- runtime binary location
- cookie file
- socket directory
- cgroup v2
- `nft`
- protocol-vector path

Warnings and failures include structured `EK_*` codes when available.

```sh
ek doctor
ek --format json doctor
```

Use this before debugging the daemon. If `doctor` reports a code, pass it to
`ek explain`.

### `ek explain`

Reads the structured error catalog and explains operator-facing codes.

```sh
ek explain EK_RUNTIME_HANDSHAKE_FAILED
ek explain RUNTIME_HANDSHAKE_FAILED
ek explain --list
ek explain --component audit
ek --format json explain EK_AUDIT_CHAIN_BROKEN
```

The `EK_` prefix is optional for a single-code lookup. Component filters use
the catalog component name, for example `ct`, `runtime`, `audit`, `nft`, or
`host`.

### `ek dsl compile`

Compiles an Elixir stack file to an Erlang term file using the bundled Elixir
runtime.

```sh
ek dsl compile stack.exs
ek dsl compile stack.exs -o stack.term
ek dsl compile stack.exs --output stack.term
```

Without `-o`, `stack.exs` writes `stack.term` beside the source file. The
compiler looks for Elixir in the installed release, in `dist/elixir` during
source-tree development, or via `EK_ELIXIR_HOME`.

## Remote Commands

Remote commands need the cookie file and a reachable target node. They connect
as a hidden node named `ek_<pid>@<hostname>`.

### Node

```sh
ek node ping
ek ping
ek node version
ek --version
ek -V
ek version
ek node health
```

`node ping` prints `pong` on success. `node version` prints the running
erlkoenig application version on the target node. `--version`, `-V`, and
`version` print the local `ek` CLI version without contacting the node.
`node health` prints the node uptime and the number of active top-level
supervisor children.

### Stack Lifecycle

```sh
ek up <file.exs|file.term>
ek down <file.exs|file.term>
ek down --all
```

`up` is the normal deploy path. For `.exs` input it compiles the file to a
sibling `.term`, then loads the term file. For `.term` input it loads the file
directly.

`down <file>` reads the declared container names from the file and stops those
containers. Bare `down` is a usage error; use `down --all` to explicitly stop
every running container on the target node.

### Config

```sh
ek config validate <file.term>
ek config load <file.term>
ek config reload <file.term>
```

`config validate` parses and validates a term file without changing running
state. `config load` is the low-level load path. `config reload` applies a
delta against live state.

For operator deployments prefer:

```sh
ek dsl compile stack.exs -o /tmp/stack.term
ek config validate /tmp/stack.term
ek up /tmp/stack.term
```

### Containers

```sh
ek ps
ek ct list
ek inspect <name-or-id>
ek ct inspect <name-or-id>
ek stop <name-or-id>
ek ct stop <name-or-id>
```

`ek ps` is an alias for `ek ct list`. Names resolve against both the DSL name
and the internal container id.

`ct inspect` prints the full state map and appends a lifecycle timeline in
table output. In JSON output the timeline is included as a field.

### Pods

```sh
ek pod list
ek pod list --all
```

Lists active pod supervisors and their non-terminal child count. Pods whose
children are all stopped/failed are hidden by default; use `--all` for the
post-mortem supervisor view.

### Volumes

```sh
ek vol list
ek vol list --container <name>
ek vol inspect <uuid|persist-name>
ek vol destroy <uuid> --yes
ek vol orphans
ek vol set-quota <uuid> <size>
```

`vol inspect` accepts either a volume UUID or the persistent volume name from
the DSL. `vol set-quota` accepts the same size syntax as the DSL, such as
`1G`, `500M`, or integer bytes. Setting `0` clears enforcement while keeping
the project binding. Quota updates are strict by default: if the kernel
project-quota command cannot be applied, the command fails and `quota_bytes`
is not updated.

`vol destroy <uuid> --yes` removes metadata and the on-disk directory. The
`--yes` flag is required because persistent volumes may contain real data.

### Quarantine

```sh
ek quarantine list
ek quarantine add <sha256-hex>
ek quarantine add <sha256-hex> --reason <atom>
ek quarantine remove <sha256-hex>
```

Hashes are SHA-256 as 64 hex characters. Input is case-insensitive. Manual
quarantine uses reason `manual` unless `--reason` is provided. Output is
lowercase hex and does not include a `0x` prefix.

### Admission

```sh
ek admission snapshot
```

Prints the spawn-admission gate state: host in-flight count, queued count, and
per-zone in-flight counts. Use this when container starts appear delayed but
not failing.

### NFT Counters

```sh
ek nft counters
ek --format json nft counters
```

`nft counters` prints live nft counter rates. Each row is scoped to the nft
table that produced the counter.

### Interactive Firewall

```sh
ek firewall status
ek firewall events
ek firewall events --limit 20
ek firewall watch
ek --format json firewall status
ek --format json firewall events
ek --format json firewall watch
```

`firewall status` shows the read-side health of the interactive firewall:
event-buffer cursor, buffered event count, waiting watch clients, subscribed
native groups, and conntrack guard statistics when the guard is running.

`firewall events` prints the newest canonical firewall events from the
node-local event buffer, oldest first. The buffer is fed from Erlkoenig's
native nft/guard event groups and normalized by the daemon; it is not parsed
from `journalctl` or shell output.

`firewall watch` follows the same stream live. In JSON mode, `watch` emits one
JSON object per line so dashboards and shell consumers can process the stream
incrementally. The snapshot command emits a JSON array.

Typical event kinds include `firewall_packet`, `counter_rate`,
`scan_suspect`, `slow_scan`, `honeypot`, `threat_ban`, and
`threat_unban`. Canonical events include the nft `table` and authoritative
`table_owner` (`host`, `zone`, `ct`, or `unknown`) when the event is tied to an
nft table. Fields are additive; consumers should ignore unknown keys.

## Common Workflows

### Preflight A Host

```sh
ek doctor
ek explain EK_HOST_CGROUP_V2_MISSING
```

`doctor` is the first command to run on a target host. It separates host/setup
problems from daemon/runtime problems.

### Deploy A Stack

```sh
ek dsl compile stack.exs -o /tmp/stack.term
ek config validate /tmp/stack.term
ek up /tmp/stack.term
ek ps
```

Validate before `up` when editing a stack manually. For routine deploys,
`ek up stack.exs` is enough because it compiles automatically.

### Inspect A Failed Container

```sh
ek ps
ek ct inspect hello-0-web
journalctl -u erlkoenig -n 200
ek explain EK_CT_SPAWN_TIMEOUT
```

Use `ct inspect` for state, cgroup stats, network state, and lifecycle
timeline. Use `ek explain` for any `EK_*` code in logs.

### Work With Volumes

```sh
ek vol list --container pg-0-postgres
ek vol inspect pg-data
ek vol set-quota ek_vol_35766831dfb3738d 20M
ek vol orphans
```

Use persistent names for lookup, UUIDs for destructive or mutating actions.

### Lift A Quarantine

```sh
ek quarantine list
ek quarantine remove <sha256-hex>
ek up stack.term
```

Only remove a quarantine after the binary or policy issue is understood. The
quarantine is intentionally explicit so crash-loop or signature failures do
not silently resume.

### Debug Spawn Backpressure

```sh
ek admission snapshot
```

If queued work grows while host in-flight stays at the configured maximum, the
host is saturated. Tune admission limits in runtime config rather than raising
container retry loops.

## Output For Tools

Use JSON when scripts need stable fields:

```sh
ek --format json ct list | jq '.[] | select(.zone == "db")'
ek --format json explain --component audit
ek --format json doctor | jq '.[] | select(.status != "ok")'
```

Use plain output for simple line-oriented shell pipelines:

```sh
ek --format plain ct list | wc -l
ek vol list | awk '/pg-data/ {print $1}'
```

## JSON Output Contract

`ek --format json …` produces a stable, tool-friendly schema. Plain and
table output are operator-readable conveniences and are **not** part of
the machine contract — only `--format json` is.

### Stability promise

- Field names and value types are stable across minor releases.
- New fields may be added; existing ones are not renamed or removed
  without a deprecation cycle and a major-version bump.
- **Key ordering is not contractual.** Decode the JSON and look up keys;
  do not match strings.
- Commands that don't surface structured data (`ek up`, `ek down`,
  `ek ct stop`, `ek quarantine add`, …) currently emit plain text in
  every format. They will move to JSON envelopes in a later phase.

### Type rules

| Internal Erlang form          | JSON form                            |
|-------------------------------|--------------------------------------|
| atom (other than true/false)  | string                               |
| `undefined`                   | `null`                               |
| binary (UTF-8)                | string                               |
| binary (non-UTF-8)            | lowercase hex string                 |
| SHA-256 hash                  | 64-char lowercase hex string         |
| IPv4 tuple `{10,10,0,2}`      | `"10.10.0.2"`                        |
| IPv6 tuple                    | RFC-5952 compressed string           |
| pid                           | string, e.g. `"<0.123.0>"`           |
| reference                     | string                               |
| map keys                      | snake_case strings                   |
| timestamps (unix-ms)          | dual: ISO-8601 UTC + `<field>_ms`    |

If `ek` ever emits a value it doesn't have an explicit normalizer for,
it prints a one-shot `notice:` line on stderr (once per command run).
That's a drift signal — please report it.

### Per-command schemas

`ek --version`, `ek -V`, `ek version`:
```json
{"version": "0.9.0"}
```

`ek node health`:
```json
{"uptime_ms": 1063408, "sup_children": 15}
```

`ek ct list` — array of:
```json
{"name": "web-0", "state": "running", "ip": "10.10.0.2",
 "zone": "dmz", "restart_count": 0}
```

`ek ct inspect <name>` — full container record. Fields include
`id`, `name`, `binary`, `state`, `zone`, `os_pid`, `restart`,
`restart_count`, `seccomp`, `args`, `caps`, `volumes`, `ports`,
`netns_path`, `socket_path`, `handshake`, plus nested `net_info`,
`stats`, `limits`, `exit_info`, `error_reason`, and the synthesized
`timeline` array (objects with `step` and `status`, in fixed lifecycle
order). Missing values are `null`. The schema is additive — new fields
may appear; existing ones don't disappear.

`net_info` carries: `ip`, `gateway`, `netmask`, `zone`, `iface`,
plus a nested `attach` object (`mode`, `os_pid`, `slave`).

`ek pod list` — array of:
```json
{"name": "web", "pid": "<0.99.0>", "children": 3}
```
`children` is the count of containers in non-terminal state. Pods whose
containers have all reached `stopped` or `failed` are filtered out —
those container processes are kept alive for post-mortem inspection
(see `ek ct inspect`) but are not "running" from an operator
perspective.

`ek vol list`, `ek vol inspect <uuid|persist>`:
```json
{"uuid": "ek_vol_…", "container": "pg-0",
 "persist": "data", "host_path": "/var/lib/erlkoenig/volumes/…",
 "lifecycle": "persistent", "quota_bytes": 1073741824}
```
`quota_bytes` is `null` when no quota is set.

`ek vol orphans` — array of `{"uuid": "…"}`. Lists **disk-orphan**
directories under the volumes root that have no metadata record —
typically from interrupted `vol destroy` operations. To find volumes
whose owner container is no longer running, diff `vol list` against
`ct list` on the `container` field.

`ek quarantine list` — array of:
```json
{"hash": "deadbeef…",
 "reason": {"kind": "crashloop", "count": 5, "window_ms": 60000},
 "since": "2026-04-27T12:34:56.789Z",
 "since_ms": 1777293296789}
```
`reason` is a string for atoms (`"manual"`) and a structured object
for known tuples (currently only `crashloop`).

`ek admission snapshot`:
```json
{"host_in_flight": 1, "queued": 0, "zone_in_flight": {"dmz": 1}}
```

`ek nft counters` — array of live counter rates:
```json
{"table": "erlkoenig_host",
 "name": "egress",
 "packets": 12,
 "bytes": 960,
 "total_packets": 1200,
 "total_bytes": 96000,
 "pps": 6.0,
 "bps": 480.0,
 "interval": 2000}
```

`ek firewall status`:
```json
{"events": {"running": true, "cursor": 12, "buffered": 3,
            "max_events": 1024, "waiting_clients": 0,
            "groups": ["nflog_events", "counter_events", "ct_guard_events"]},
 "guard": {"active_actors": 1, "active_bans": 0}}
```

`ek firewall events` — array of canonical firewall event envelopes:
```json
{"seq": 8,
 "id": "fw-1778147168000-1",
 "ts_mono": 123456,
 "ts_wall": 1778147168000,
 "source": "nflog",
 "severity": "notice",
 "kind": "firewall_packet",
 "table": "erlkoenig_host",
 "table_owner": "host",
 "chain": "input",
 "src_ip": "203.0.113.44",
 "dst_ip": "10.0.0.1",
 "proto": "tcp",
 "dst_port": 22,
 "reason": "packet_observed",
 "evidence": {},
 "labels": ["firewall", "packet"]}
```

`ek --format json firewall watch` emits the same envelope shape as newline
delimited JSON, one event object per line.

### Out of scope for `--format json`

- AMQP event payloads — separate contract; see `docs/AMQP_EVENTS.md`.
- Wire protocol between BEAM and `erlkoenig_rt` — separate contract.
- Plain/table output — operator-readable, not machine-stable.

## Exit Behavior

Successful commands exit `0`. Unknown commands, failed diagnostics with
blocking failures, connection failures, missing files, unknown error codes,
and remote RPC failures exit non-zero and print a one-line `error:` message to
stderr.

Remote API mismatches are reported as an `undef` remote call with a hint that
the deployed release may be older than the CLI.

## Troubleshooting

### `can't read cookie`

Check the default path and permissions:

```sh
ls -l /etc/erlkoenig/cookie
sudo cat /etc/erlkoenig/cookie
```

Override with:

```sh
ek --cookie-file ~/.config/erlkoenig/cookie node ping
```

### `can't reach erlkoenig at 'erlkoenig@...'`

Check the service, cookie, and hostname resolution:

```sh
systemctl status erlkoenig
md5sum /opt/erlkoenig/cookie /etc/erlkoenig/cookie
getent hosts "$(hostname)"
```

If the node name is not the default, pass it explicitly:

```sh
ek --node erlkoenig@myhost node ping
```

### `no Elixir bundle found`

`dsl compile` needs the bundled Elixir tree. On an installed host it should be
under `/opt/erlkoenig/elixir`. In a source tree it should be under
`dist/elixir`. For custom layouts:

```sh
EK_ELIXIR_HOME=/path/to/elixir ek dsl compile stack.exs
```

### `validation failed`

Run the compiler separately and validate the generated term:

```sh
ek dsl compile stack.exs -o /tmp/stack.term
ek config validate /tmp/stack.term
```

Then inspect the term file if needed:

```sh
erl -noshell -eval 'io:format("~p~n", [file:consult("/tmp/stack.term")]), halt().'
```

### `unknown error code`

Confirm the installed CLI can find the error catalog:

```sh
ek explain --list
```

In source-tree development, run from the repository root so
`apps/erlkoenig/priv/error_catalog.term` is visible.

## Not In The Packaged CLI Yet

The shipped escript is intentionally one-shot. These names are not current
`ek` subcommands:

- `ek logs`
- `ek top`
- `ek sign`
- `ek verify`
- `ek pki`
- `ek fw`
- `ek threat`
- `ek events tail`

Some equivalent functionality exists through Erlang modules, AMQP consumers,
or separate tools, but it is not exposed as a stable packaged CLI command yet.
