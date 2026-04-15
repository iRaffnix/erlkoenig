defmodule MinimalVolumeOpts do
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════
  # Minimal Example — Volume mit Mount Options
  # ══════════════════════════════════════════════════════════
  #
  # Zeigt nur eins: wie man einem Volume Mount-Flags mitgibt
  # (`opts:` Schlüssel). Die Host-Seite des Volumes lebt unter
  # `/var/lib/erlkoenig/volumes/app-0-svc/uploads/` und wird
  # als bind-mount mit MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME
  # gemountet — ausführbare Uploads sind damit abgeschaltet.
  #
  # Starten:
  #   mix run -e '
  #     [{mod, _}] = Code.compile_file("examples/minimal_volume_opts.exs")
  #     mod.write!("/tmp/minimal_volume_opts.term")
  #   '
  #   erlkoenig eval 'erlkoenig_config:load(<<"/tmp/minimal_volume_opts.term">>).'

  host do
    ipvlan "app-net", parent: {:dummy, "ek_app"}, subnet: {10, 0, 0, 0, 24}
  end

  pod "app", strategy: :one_for_one do
    container "svc",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      args: ["600"],
      zone: "app-net",
      replicas: 1,
      restart: :permanent do

      # ── Die einzige interessante Zeile ───────────────────
      #
      # `persist:` — Name des Host-seitigen Datenbereichs
      # `opts:`    — mount(8)-Syntax, wird beim Konfig-Laden
      #              durch `erlkoenig_mount_opts:parse/1` geprüft.
      #              Tippfehler (`nosudi`) failen laut beim Laden.
      volume "/uploads", persist: "uploads",
                         opts: "rw,nosuid,nodev,noexec,relatime"
    end
  end
end
