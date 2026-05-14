# AMQP Event Contract

This document is the operator-facing contract for events published by
`erlkoenig_amqp_codec`. It documents the JSON envelope, routing-key families,
payload field names, and field types that external consumers can rely on.

The source of truth for implementation remains
`apps/erlkoenig/src/erlkoenig_amqp_codec.erl`. Changes to field names, field
types, routing-key families, or structured `code` values are compatibility
changes and must follow the stability rules in `CONTRIBUTING.md`.

## Stability Rules

Stable:

- Envelope field names and types.
- Routing-key families listed here.
- Payload field names and types for existing events.
- Structured `code` values in `error.*.*` payloads.

Allowed in minor releases:

- New routing-key families.
- New payload fields.
- New structured error codes.
- New event variants under an existing family.

Breaking:

- Removing or renaming an existing payload field.
- Changing a field type.
- Removing an existing routing-key family.
- Reusing an existing field name with different meaning.
- Removing `code` from structured error payloads.

Deprecations must warn for at least two minor releases before removal.

## Transport

Events are published to a topic exchange. The default exchange name is
`erlkoenig.events`; deployments may override it in the AMQP sys.config block.
Messages are published with AMQP persistent delivery mode. The message body is
the JSON envelope below.

The AMQP routing key and the envelope `key` field are the same value.

## Configuration

AMQP publishing is off by default. Enable it in `sys.config`:

```erlang
{erlkoenig, [
    {amqp, #{
        enabled  => true,
        host     => "rabbitmq.internal",
        port     => 5672,
        user     => <<"erlkoenig">>,
        password => <<"…">>,
        exchange => <<"erlkoenig.events">>
    }}
]}
```

Operationally relevant keys:

| Key | Default | Effect |
|-----|---------|--------|
| `amqp.enabled` | `false` | Master switch. When `false`, the publisher gen_server is not started and no events are forwarded. |
| `amqp.exchange` | `<<"erlkoenig.events">>` | Topic exchange the publisher declares (durable) and publishes to. |
| `volume_stats_enabled` | `true` | Toggles the `stats.volume.*` event family at the source. |
| `quarantine_enabled` | `true` | Toggles the `security.<hash-prefix>.quarantined` and `unquarantined` events. |

`amqp.enabled = false` is fail-closed: a misconfigured broker cannot wedge the
runtime, but consumers also see no events.

## Envelope

Every encoded AMQP event is a JSON object:

```json
{
  "v": 2,
  "ts": "2026-04-05T18:00:00.000Z",
  "node": "erlkoenig@host",
  "key": "container.web-0-nginx.started",
  "payload": {}
}
```

Fields:

| Field | Type | Meaning |
|-------|------|---------|
| `v` | integer | Envelope version. Current value is `2`. |
| `ts` | string | UTC timestamp in `YYYY-MM-DDTHH:MM:SS.mmmZ` form. |
| `node` | string | Erlang node name that encoded the event. |
| `key` | string | AMQP topic routing key. Same value used for publish routing. |
| `payload` | object | Event-specific payload. |

Unknown internal events are skipped and do not reach AMQP.

## Encoding Rules

Payloads are JSON objects with string keys.

General value conversion:

| Erlang value | JSON value |
|--------------|------------|
| atom | string |
| binary/list text | string |
| integer | number |
| float | number |
| map | object with recursively encoded string keys |
| IPv4 tuple or 4-byte non-UTF-8 binary on IP fields | dotted string |
| IPv6 tuple or 16-byte binary on IP fields | IPv6 string from `inet:ntoa/1` |
| non-UTF-8 binary | uppercase hex string |
| other term | Erlang `~p` string |

Special cases:

- Missing container stop exit data uses JSON `null` for `exit_code` and
  `signal`.
- Quarantine hashes are lowercase hex strings when the source value is a raw
  SHA-256 binary.
- Error payloads stringify atoms so Python and other non-Erlang consumers do
  not need Erlang term decoding.

## Routing Keys

Routing keys use topic-exchange syntax:

```text
<category>.<entity>.<event>
```

Consumers should subscribe by prefix where possible, for example
`container.#`, `stats.#`, `error.#`, or `guard.threat.*`.

## Event Families

### Structured Errors

Routing: `error.<type>.<reason>`

Payload fields:

| Field | Type | Notes |
|-------|------|-------|
| `type` | string | Error category, for example `network`, `config`, `operator`. |
| `reason` | string | Error reason. |
| `code` | string | Stable `EK_*` identifier. |
| `context` | string | Human context. |
| `data` | object | Structured evidence. |
| `severity` | string | Severity label. |
| `source` | object | Source metadata. |
| `ts_ms` | integer | Unix time in milliseconds. |
| `container` | string | Optional container name/id. |

The `code` field is part of the stable operator contract.

Structured error events are for alerting and automation. They are emitted by
explicit `erlkoenig_error:emit/1,2` calls and route under `error.#`, for
example `error.ct.cgroup_setup_failed`. Lifecycle failures are separate
container events: `container.<name>.failed` carries the container state-machine
failure reason for timeline consumers. Operators who need pages, tickets, or
deduplicated incident aggregation should subscribe to `error.#`; operators who
need container timelines should subscribe to `container.#`.

### Container Lifecycle

Routing:

| Key | Payload |
|-----|---------|
| `container.<name>.started` | `id`, `name`, `os_pid` |
| `container.<name>.stopped` | `id`, `name`, `exit_code`, `signal` |
| `container.<name>.failed` | `id`, `name`, `reason` |
| `container.<name>.restarting` | `id`, `name`, `attempt` |
| `container.<name>.oom` | `id`, `name` |
| `container.<name>.health` | `id`, `name`, `failures` |

Legacy `container_unhealthy` events without `name` route as
`container.<id>.health` and carry `id`, `failures`.

### Aggregate Container-Cgroup Stats

Routing: `stats.system.containers`

Payload fields include `memory_current`, `memory_peak`, `memory_max`,
`memory_available`, `memory_pct`, `cpu_usec`, `pids_current`, `pids_max`,
`pids_available`, `pids_pct`, `scope`, and `ts_ms`. This event describes the
aggregate `containers/` cgroup headroom, not an individual container.

### Container Stats

Routing: `stats.<name>.<metric>`

Payload fields:

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | Container name. |
| metric fields | number/string | Metric-specific fields from cgroup polling. |

Common metrics include `memory`, `cpu`, `pids`, `pressure`, and `oom_events`.
See `doc/book/09-observability.md` for the metric field list.

### Volume Stats

Routing: `stats.volume.<container>.<persist>`

Payload includes the volume stat map plus normalized fields:

| Field | Type |
|-------|------|
| `container` | string |
| `persist` | string |
| `uuid` | string |
| `bytes` | integer |
| `inodes` | integer |
| `lifecycle` | string |

Additional numeric stat fields may be present.

### Quarantine

Routing:

| Key | Payload |
|-----|---------|
| `security.<hash-prefix>.quarantined` | `hash`, `reason`, `ts_ms` |
| `security.<hash-prefix>.unquarantined` | `hash`, `ts_ms` |

`hash-prefix` is the first 12 hex characters when available. `hash` is the
full hash string.

### Admission

Routing:

| Key | Payload |
|-----|---------|
| `admission.<scope>.accepted` | `scope`, `ts_ms` |
| `admission.<scope>.waiting` | `scope`, `ts_ms` |
| `admission.<scope>.timeout` | `scope`, `ts_ms` |

### Policy

Routing: `policy.<name>.violation`

Payload fields:

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Container id. |
| `name` | string | Container name, when available. |
| `violation_type` | string | Policy violation type. |
| `action` | string | Policy action. |
| `detail` | string | Optional detail. |

Legacy events without `name` route as `policy.<id>.violation` and carry
`id`, `detail`.

### Control

Routing: `control.<scope>.<action>`

Payload fields:

| Field | Type |
|-------|------|
| `action` | string |
| `status` | string |
| `details` | object |

Known scopes are `nft` and `set`.

### Conntrack

Routing:

| Key | Payload |
|-----|---------|
| `conntrack.flow.new` | flow fields |
| `conntrack.flow.destroy` | flow fields |
| `conntrack.alert.mode` | `mode` |

Flow fields:

| Field | Type |
|-------|------|
| `src` | string |
| `dst` | string |
| `sport` | integer |
| `dport` | integer |
| `proto` | string or integer |
| `timeout` | integer |

Fields are included when known.

### Firewall

Routing:

| Key | Payload |
|-----|---------|
| `firewall.<chain>.packet` | canonical `firewall_packet` envelope |
| `firewall.<chain>.drop` | canonical `counter_rate` envelope |
| `firewall.<name>.threshold` | `id`, `name`, `metric`, `current`, `threshold` |
| `guard.threat.suspect` | canonical `scan_suspect` envelope |

The interactive firewall path normalizes NFLOG packets, nft counter rates, and
guard/correlation decisions through `erlkoenig_firewall_event` before AMQP
encoding. Counter events with `packets = 0` are skipped, so consumers only see
active rate samples.

Common canonical envelope fields include `id`, `source`, `severity`, `kind`,
`table`, `table_owner`, `chain`, `counter`, `src_ip`, `dst_ip`, `proto`,
`src_port`, `dst_port`, `verdict`, `reason`, `evidence`, and `labels`.
`table` and `table_owner` are populated when the nft event source can map the
packet or counter back to an explicit owner table; consumers must still tolerate
`unknown` for older or unscoped producers. Payload fields remain additive.

### Guard

Routing:

| Key | Payload |
|-----|---------|
| `guard.threat.ban` | `ip`, `reason`, `duration`, `ban_count` |
| `guard.threat.unban` | `ip` |
| `guard.threat.honeypot` | `ip`, `port`, `duration`, `reason` |
| `guard.threat.slow_scan` | `ip`, `ports`, `window`, `reason` |
| `guard.threat.suspect` | `ip`, `ports`, `reason` |
| `guard.threat.ban_failed` | `ip`, `reason` |
| `guard.threat.unban_failed` | `ip`, `code` |
| `guard.stats.summary` | `actors`, `bans`, `events_seen`, `tracked_events` |

### System

Routing:

| Key | Payload |
|-----|---------|
| `system.config.loaded` | `file`, `pods`, `zones`, `nft_tables` |
| `system.config.failed` | `file`, `reason` |
| `system.firewall.applied` | `table` |
| `system.firewall.failed` | `table`, `reason` |
| `system.log.overflow` | `name`, `dropped_count`, `dropped_bytes` |
| `system.log.disconnected` | `name` |

### Security Signatures

Routing:

| Key | Payload |
|-----|---------|
| `security.<name>.verified` | `id`, `name`, `signer` |
| `security.<name>.rejected` | `id`, `name`, `reason` |

### Process Metrics

Routing: `metrics.<name>.<type>`

Payload fields:

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Container id. |
| `name` | string | Container name, when available. |
| `type` | string | Metric type. |
| `timestamp_ns` | integer | Optional runtime timestamp. |
| `comm` | string | Optional process command name. |

Legacy events without `name` route as `metrics.<id>.<type>` and carry `id`,
`type`.

### Audit Chain

Routing:

| Key | Payload |
|-----|---------|
| `audit.chain.sealed` | `sealed_path`, `event_count`, `byte_count`, `anchor` |
| `audit.chain.broken` | `path`, `line`, `reason` |

### Capability Framework

Routing: `capability.unmet.<capability>`

Payload fields:

| Field | Type |
|-------|------|
| `id` | string |
| `name` | string |
| `capability` | string |
| `action` | string |

The capability name may contain dots, for example `capability.unmet.dns.local`.

## Consuming Events

erlkoenig only declares the topic exchange. Each consumer declares and binds
its own queue with the topic patterns it cares about. Concrete pattern using
the AMQP 0-9-1 protocol (e.g. via `pika`):

```python
channel.exchange_declare(
    exchange="erlkoenig.events",
    exchange_type="topic",
    durable=True,
)
channel.queue_declare(queue="my-audit-tap", durable=True)
channel.queue_bind(
    queue="my-audit-tap",
    exchange="erlkoenig.events",
    routing_key="error.#",        # all structured errors
)
channel.queue_bind(
    queue="my-audit-tap",
    exchange="erlkoenig.events",
    routing_key="audit.chain.#",  # audit chain events
)
```

Bind on as many topic patterns as you need; `#` matches one or more dot
segments, `*` matches exactly one. Common useful subscriptions:

- `error.#` — every structured error code (operator dashboards, paging).
- `container.#` — full container lifecycle.
- `stats.#` — every gauge series (memory, CPU, PIDs, pressure, OOM, volumes).
- `guard.threat.#` — threat detection (bans, honeypots, scans).
- `audit.chain.#` — audit-chain seal/break (compliance pipelines).

## Consumer Guidance

Use the envelope `key` field as the canonical routing key inside decoded JSON.
AMQP `method.routing_key` should match it, but consumers that process archived
JSON should not depend on AMQP metadata being available.

Consumers should ignore unknown fields and unknown routing keys. Treat missing
documented fields as producer bugs unless the field is explicitly marked
optional.

For structured errors, prefer branching on `payload.code` rather than parsing
human-readable text. The same `EK_*` codes appear in `ek explain <code>` and
in the CLI's `--format json` error output.

## Relation to the CLI JSON Contract

The AMQP event schema is a **separate contract** from the CLI `--format json`
schema documented in [docs/CLI.md](CLI.md#json-output-contract). They share
encoding conventions (atoms→strings, IPv4 tuples→dotted strings, snake_case
keys), but the two surfaces evolve independently. The firewall CLI reads from
the node-local `erlkoenig_firewall_events` buffer, while AMQP receives encoded
events from the publisher path. A consumer reading `stats.web-0.memory` from
AMQP cannot assume the same field shapes as `ek --format json ct inspect web-0`.

## Source of Truth

Implementation: `apps/erlkoenig/src/erlkoenig_amqp_codec.erl` (encoder),
`erlkoenig_amqp_publisher.erl` (transport), `erlkoenig_amqp_forwarder.erl`
(gen_event tap), `erlkoenig_amqp_nft_sub.erl` (pg tap for nft events).

Tests: `apps/erlkoenig/test/erlkoenig_amqp_codec_tests.erl` — every routing
key family has at least one assertion against decoded JSON.
