# Chapter 8 — Persistent Volumes

A volume is a directory on the host bind-mounted into a container with
chosen mount options. erlkoenig manages its identity, permissions,
lifecycle, and optional disk quota. Volumes are declared inside a
container block and survive container restarts by default; an
ephemeral flag makes them disappear with the container.

## The mental model

A volume declaration in the DSL names *what the container sees*:

```elixir
volume "/data", persist: "app-data"
```

- **`"/data"`** is the container-side mount point — where the
  application looks for the directory.
- **`persist: "app-data"`** is the logical name. The
  `(container, persist)` pair is stable: the same container always
  resolves to the same volume, even across restarts.

The host side is managed. erlkoenig generates a UUID
(`ek_vol_<16hex>`) on first use and stores the data at
`/var/lib/erlkoenig/volumes/<uuid>/`. A symlink tree under
`/var/lib/erlkoenig/volumes/by-name/<container>/<persist>` points to
the UUID directory for operator convenience. The metadata lives in a
DETS index at `/var/lib/erlkoenig/volumes/.index.dets` — the volume
store is the single source of truth.

A container never sees the UUID path. It only sees its own
`/data`, chowned to the container's UID on first creation with
mode `0750`.

## Declaration options

| Option         | Type                 | Default   | Meaning                                             |
|----------------|----------------------|-----------|-----------------------------------------------------|
| `:persist`     | binary               | required  | Logical name, `[a-z0-9][a-z0-9_-]*`                 |
| `:read_only`   | boolean              | `false`   | Short-hand for `opts: "ro"`                         |
| `:opts`        | binary               | `nil`     | Full `mount(8)` option string                       |
| `:ephemeral`   | boolean              | `false`   | If `true`, destroy the volume on container stop     |
| `:quota`       | size string or bytes | `nil`     | Hard disk limit via XFS project quota               |

A full hardened volume:

```elixir
volume "/uploads", persist: "app-uploads",
                   opts: "rw,nosuid,nodev,noexec,relatime",
                   quota: "5G"
```

## Mount options and security

The `opts:` string follows `mount(8)` syntax. The parser
(`erlkoenig_mount_opts`) recognises the standard per-mount flags
and is strict about unknown bare tokens — a typo like `"nosudi"`
fails at load time with `{unknown_flag, <<"nosudi">>}` rather than
silently slipping through.

Flag names supported: `ro`, `rw`, `nosuid`/`suid`, `nodev`/`dev`,
`noexec`/`exec`, the atime family (`noatime`, `relatime`,
`strictatime`, `nodiratime`), `bind`/`rbind`, and propagation modes
(`private`, `slave`, `shared`, `unbindable`, each with `r`-prefix
variants). Conflicting flags follow mount(8) last-wins semantics;
conflicting propagation modes raise `{conflicting_propagation, ...}`.

Four security flags matter most on volumes:

- **`ro`** — writes fail with `EROFS`. Use for configuration that
  the container reads but should never modify.
- **`nosuid`** — SUID bits on files in the volume are ignored. Use
  everywhere.
- **`nodev`** — no device nodes. Use everywhere.
- **`noexec`** — `execve()` on files in the volume fails. Useful for
  upload areas: a compromised handler can drop a file but can't run
  it. Note: `noexec` does not stop an interpreter from reading a
  script; for that you need Landlock or seccomp.

## Lifecycle

**Persistent** (the default): the volume survives container destroy.
Its data is left on disk; removal requires an explicit
`erlkoenig_volume_store:destroy/1`.

**Ephemeral**: `ephemeral: true` marks the volume for cleanup when
the container enters `stopped` or `failed`. The metadata record and
the UUID directory are removed atomically. Use ephemerals for
per-run scratch space, caches that aren't worth keeping, or test
containers.

Both lifecycles coexist within one container. A typical hardened
setup mixes them:

```elixir
container "app", binary: "...", zone: "dmz",
  replicas: 2, restart: :permanent do

  # persistent: rw application state
  volume "/data",    persist: "app-data"

  # persistent, read-only config
  volume "/etc/app", persist: "app-config", read_only: true

  # persistent upload area, no executable files
  volume "/uploads", persist: "app-uploads",
                     opts: "rw,nosuid,nodev,noexec,relatime"

  # ephemeral scratch — gone when the container dies
  volume "/scratch", persist: "scratch",
                     opts: "rw,nosuid,nodev,noexec",
                     ephemeral: true
end
```

Two replicas of this container produce two independent sets of
volume UUIDs; each replica has its own `/data`, `/uploads`, and
`/scratch`. Configuration is shared content-wise via the `/etc/app`
volume — all replicas map to the same UUID because persist name +
container name resolve to the same key.

## Quota

XFS project quotas enforce a hard byte limit per volume. The volume
store allocates a project ID at creation, binds it to the volume
directory, and sets the limit via `xfs_quota`. Writes past the
limit fail with `EDQUOT`; reads are unaffected.

`quota: "1G"` accepts human-readable units with binary multipliers:
`K`, `M`, `G`, `T`, `P`, case-insensitive, optional trailing `B`.
Passing an integer treats it as raw bytes. Omitting the option or
`quota: 0` disables quota.

Quotas are best-effort at the subprocess layer. If the volumes
filesystem isn't mounted with `prjquota`, or the `xfs_quota` binary
is missing, or the volumes root looks like a test fixture (paths
under `/tmp/`), the call is skipped with a warning. The metadata
records the requested limit regardless, so a later move to a proper
XFS mount picks it up on reconciliation.

Live adjustment: `erlkoenig_volume_store:set_quota/2` updates an
existing volume's limit without touching its data. Setting the limit
to zero clears enforcement while keeping the project binding, so
subsequent raises don't need to re-bind.

## Observability

Every configured volume is polled periodically by
`erlkoenig_volume_stats`. The default interval is 60 seconds; it's
tunable via `sys.config` keys `volume_stats_interval_ms` and
`volume_stats_enabled`. For each volume the emitter walks the
directory tree and publishes an AMQP event
`stats.volume.<container>.<persist>` carrying `bytes`, `inodes`,
`lifecycle`, `uuid`, and a millisecond timestamp. The walk is pure
Erlang — no `du` subprocess. Dashboards and alerting consume the
events directly.

## What the chapter links to

- The `volume` declaration lives inside the `container` block
  (→ Chapter 4).
- Host-side XFS-on-loop setup and the `prjquota` mount flag are in
  → Chapter 15.
- The wire format and mount sequence (MS_BIND → MS_REMOUNT →
  propagation) are described in → Chapter 12.
