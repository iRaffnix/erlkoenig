# Chapter 8 — Persistent Volumes

A volume is a directory on the host bind-mounted into a container with
chosen mount options. erlkoenig manages its identity, permissions,
lifecycle, and optional disk quota. Volumes are declared inside a
container block and survive container restarts by default; an
ephemeral flag makes them disappear with the container.

## Prerequisite: host backing

All volumes live under `/var/lib/erlkoenig/volumes/`. That path must
be a dedicated XFS filesystem mounted with `prjquota` — otherwise
quotas don't work, `nosuid`/`noexec` on child mounts don't take
effect, and one container filling a volume can fill the host root
filesystem. On single-disk hosts an XFS-on-loop image is the
recommended setup: one `truncate`, one `mkfs.xfs`, one `mount -o
loop,prjquota` and you're done. The one-time procedure is in
→ Chapter 15. The rest of this chapter assumes the backing is in
place.

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
`/data`, chowned to the container's declared `uid:`/`gid:` on
first creation with mode `0750`. If no UID is declared
(the default is `0`) the volume ends up owned by root — set
`uid:` explicitly on the container block when running as an
unprivileged user so the bind-mount is writable without extra
capabilities.

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
fails at parse time with `{error, {unknown_flag, <<"nosudi">>}}`
rather than silently slipping through.

Flag names supported: `ro`, `rw`, `nosuid`/`suid`, `nodev`/`dev`,
`noexec`/`exec`, the atime family (`noatime`, `relatime`,
`strictatime`, `nodiratime`), `bind`/`rbind`, and propagation modes
(`private`, `slave`, `shared`, `unbindable`, each with `r`-prefix
variants). Conflicting flags follow mount(8) last-wins semantics;
conflicting propagation modes return
`{error, {conflicting_propagation, Existing, New}}`.

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
the container enters `stopped` or `failed`. The cleanup removes the
UUID directory, the by-name symlink, and the DETS metadata record
in sequence. Use ephemerals for per-run scratch space, caches that
aren't worth keeping, or test containers.

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
volume UUIDs; each replica has its own `/data`, `/uploads`,
`/etc/app`, and `/scratch`. The volume key is
`(container-name, persist)` where container-name includes the
replica index (`web-0-app`, `web-1-app`), so every replica resolves
to its own UUID for every volume — including read-only ones.
Sharing configuration across replicas requires an external step:
populate the volume content before the containers start, or use a
host-side config directory that each replica's volume points to.

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
records the requested limit regardless. Reconciliation happens on
the next container ensure cycle — typically the next container
restart — not via a background loop. A host moved to a proper XFS
mount picks up the stored quotas the next time the affected
containers come up.

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

## End-to-end: a PostgreSQL container with quota

This is the complete walk-through. Start from a fresh host with
XFS backing mounted (→ Chapter 15). By the end you have a
running PostgreSQL container with a 10 GB persistent data volume,
a read-only config mount, an ephemeral scratch area, and live
disk-usage events on the AMQP bus.

**1. Stack file.** Save as `~/pg.exs`:

```elixir
defmodule PgStack do
  use Erlkoenig.Stack

  host do
    ipvlan "db",
      parent: {:dummy, "ek_db"},
      subnet: {10, 90, 0, 0, 24}
  end

  pod "pg", strategy: :one_for_one do
    container "postgres",
      binary: "/opt/postgres/bin/postgres",
      args: ["-D", "/data"],
      uid: 70, gid: 70,
      zone: "db",
      replicas: 1,
      restart: :permanent do

      # rw persistent data — 10 GB hard cap
      volume "/data", persist: "pg-data", quota: "10G"

      # ro config, operator-managed from outside
      volume "/etc/postgresql", persist: "pg-config",
                                read_only: true

      # ephemeral WAL archive staging — gone on container stop
      volume "/scratch", persist: "pg-wal-stage",
                         opts: "rw,nosuid,nodev,noexec",
                         ephemeral: true

      publish interval: 5_000 do
        metric :memory
        metric :pids
      end
    end
  end
end
```

**2. Compile and load.**

```bash
ek dsl compile ~/pg.exs -o /tmp/pg.term
ek config_load /tmp/pg.term
ek ps
```

`ek ps` shows `pg-0-postgres` in state `running` once the namespaces
and bind mounts are in place.

**3. Inspect what erlkoenig created on disk.**

```bash
ek volume list
# pg-data      ek_vol_1a2b3c4d...  /var/lib/erlkoenig/volumes/ek_vol_1a2b3c4d
# pg-config    ek_vol_2b3c4d5e...  /var/lib/erlkoenig/volumes/ek_vol_2b3c4d5e
# pg-wal-stage ek_vol_3c4d5e6f...  /var/lib/erlkoenig/volumes/ek_vol_3c4d5e6f  (ephemeral)

ls -la /var/lib/erlkoenig/volumes/by-name/pg-0-postgres/
# data         -> ../../ek_vol_1a2b3c4d
# config       -> ../../ek_vol_2b3c4d5e
# wal-stage    -> ../../ek_vol_3c4d5e6f
```

The UUID directories are chowned to `70:70` with mode `0750` so the
postgres process (running as UID 70 inside the container) can read
and write, while unrelated host users are shut out.

**4. Populate the read-only config from the host side.** The
container mounts `/etc/postgresql` as `ro`, but the *host* sees
the underlying UUID directory as `rw`. Operators put config
files there directly:

```bash
cp /etc/postgresql.conf.template \
   $(ek volume inspect pg-config --format json | jq -r .host_path)/postgresql.conf
```

A container restart is not required — the bind-mount already
reflects the new file content.

**5. Watch live disk usage.** In one terminal:

```bash
event_consumer.py amqp://erlkoenig@broker 'stats.volume.pg-0-postgres.*'
```

Every 60 seconds (configurable via `volume_stats_interval_ms`)
three events arrive — one per volume — carrying `bytes`, `inodes`,
`lifecycle`, `uuid`, and `ts_ms`. Dashboards consume these
directly; no `du` walks on the host.

**6. Trigger the quota.** Inside the container (or via
`erlkoenig:exec` to get a shell):

```bash
dd if=/dev/zero of=/data/big.bin bs=1M count=11000
# write "/data/big.bin": No space left on device (EDQUOT)
```

The writer gets `EDQUOT` — not `ENOSPC` — because the hard limit
is project-level, not filesystem-level. `df` inside the container
still reports the full XFS size; only the *project* quota is
exhausted. Reads and deletes of existing data remain unaffected.

**7. Raise the quota without downtime.**

```erlang
%% From an ek remote_console or erlkoenig eval:
{ok, V} = erlkoenig_volume_store:find(<<"pg-0-postgres">>, <<"pg-data">>),
erlkoenig_volume_store:set_quota(maps:get(uuid, V), <<"20G">>).
```

The new limit takes effect immediately for subsequent writes. No
container restart, no remount, no lost connections.

**8. Stop the container and inspect cleanup.**

```bash
ek down ~/pg.exs
ek volume list
# pg-data      ek_vol_1a2b3c4d...  (persistent — still there)
# pg-config    ek_vol_2b3c4d5e...  (persistent — still there)
# pg-wal-stage                      (absent — ephemeral cleanup ran)
```

`pg-data` and `pg-config` survive because they are persistent;
their next `ek up` re-binds them to whichever container claims the
matching `(container-name, persist)` key. The ephemeral
`pg-wal-stage` directory, its by-name symlink, and its DETS
record are gone — cleanup executed when the container transitioned
to `stopped`.

**9. Destroy when you're done.**

```bash
ek volume destroy ek_vol_1a2b3c4d...
ek volume destroy ek_vol_2b3c4d5e...
```

This is the only operation that removes persistent volumes. It
is deliberately not automatic — a typo in a stack file should
never silently delete production data.

## What the chapter links to

- The `volume` declaration lives inside the `container` block
  (→ Chapter 4).
- Host-side XFS-on-loop setup and the `prjquota` mount flag are in
  → Chapter 15.
- The wire format and mount sequence (MS_BIND → MS_REMOUNT →
  propagation) are described in → Chapter 12.
