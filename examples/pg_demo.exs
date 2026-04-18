defmodule PgDemo do
  @moduledoc """
  Chapter 8 canonical example — PostgreSQL with persistent data,
  read-only config, ephemeral scratch, and a 10 MB XFS project quota.

  This is the stack walked through in doc/book/08-persistent-volumes.md
  "End-to-end: a PostgreSQL container with quota". In production, point
  `@bin` at a real postgres binary; for host-side demos the echo_server
  stand-in is enough to exercise the volume + quota pipeline.

  Preconditions:
    * XFS-on-loop backing mounted at /var/lib/erlkoenig/volumes
      with `prjquota` (see doc/book/15-volume-backing-ops.md).
    * erlkoenig daemon running.

  Usage:
    ek up       examples/pg_demo.exs
    ek ps
    ek vol list
    ek vol set-quota <uuid> 20M      # raise cap live, no restart
    ek down     examples/pg_demo.exs   # persistent volumes survive,
                                       # ephemeral scratch is cleaned
    ek vol destroy <uuid>              # only removes data explicitly
  """

  use Erlkoenig.Stack

  # Production: /usr/lib/postgresql/16/bin/postgres or similar.
  # Demo/testing: the static echo_server binary ships with the release
  # and exercises the same volume + zone wiring.
  @bin "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"

  host do
    ipvlan "db",
      parent: {:dummy, "ek_db"},
      subnet: {10, 90, 0, 0, 24}
  end

  pod "pg", strategy: :one_for_one do
    container "postgres",
      binary: @bin,
      args: ["9000"],
      uid: 70, gid: 70,
      zone: "db",
      replicas: 1,
      restart: :permanent do

      # rw persistent data -- 10 MB hard cap so the quota demo hits fast
      volume "/data", persist: "pg-data", quota: "10M"

      # ro config -- operator pushes files into the host-side UUID dir
      volume "/etc/postgresql", persist: "pg-config",
                                read_only: true

      # ephemeral WAL-stage -- gone on container stop, data never survives
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
