defmodule HardenedVolumes do
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════
  # Realistic Example — Web-App mit gehärteten Volumes
  # ══════════════════════════════════════════════════════════
  #
  # Zeigt wie die fünf üblichen Volume-Klassen typischerweise
  # konfiguriert sind, wenn Zero-Trust ernst gemeint ist:
  #
  #   /data      — rw, persistente Nutzdaten (DB, Sessions)
  #   /etc/app   — ro, vom Admin bereitgestelltes Config
  #   /uploads   — rw, aber *nicht ausführbar* (nosuid,noexec)
  #                → ein hochgeladenes Binary kann nicht als
  #                  Angriffspfad dienen
  #   /cache     — rw, tmpfs-ähnlich aber persistent; relatime
  #                spart Writeback bei vielen kleinen Lesezugriffen
  #   /scratch   — ephemer: wird beim Container-Stop zerstört
  #                (Metadata + On-Disk-Verzeichnis sauber weg)
  #
  # Jedes Volume wird pro Container-Replika separat persistiert
  # (Host-Pfad: /var/lib/erlkoenig/volumes/web-<N>-app/<persist>/).
  # Zwei Replicas → zwei unabhängige /data-Verzeichnisse.
  #
  # Starten:
  #   mix run -e '
  #     [{mod, _}] = Code.compile_file("examples/hardened_volumes.exs")
  #     mod.write!("/tmp/hardened_volumes.term")
  #   '
  #   erlkoenig eval 'erlkoenig_config:load(<<"/tmp/hardened_volumes.term">>).'
  #
  # Prüfen (im laufenden Container):
  #   # Shell in die App:
  #   erlkoenig eval 'erlkoenig:exec(Pid, ["/bin/sh"]).'
  #   # In der Shell:
  #   cat /proc/self/mountinfo | grep -E '/data|/uploads|/etc/app|/cache'
  #   # Man sieht ro, nosuid, noexec, relatime an der richtigen Stelle.

  host do
    ipvlan "web-net", parent: {:dummy, "ek_web"}, subnet: {10, 0, 0, 0, 24}

    nft_table :inet, "host" do
      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do
        # ── Standard-Härtung ──────────────────────────────
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, tcp_dport: 22

        # ── Runtime-Services ──────────────────────────────
        # erlkoenig DNS-Resolver pro Zone auf der Gateway-IP.
        # Ohne diese Regel timeoutet jedes getaddrinfo() im
        # Container. Glasbox: explizit, kein Magic-Inject
        # (Kapitel 6 Service-Catalogue).
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 24}, udp_dport: 53
      end
    end
  end

  pod "web", strategy: :one_for_one do
    container "app",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      args: ["600"],
      zone: "web-net",
      replicas: 2,
      restart: :permanent do

      # ── /data — rw persistent ────────────────────────────
      #
      # Default-Konfiguration: kein `opts:`, kein `read_only:`.
      # Mount ist `rw,suid,dev,exec` (Kernel-Defaults).
      # Passt für Datenbanken, Session-Storage, State.
      volume "/data", persist: "app-data"

      # ── /etc/app — ro config ─────────────────────────────
      #
      # Legacy-Variante: `read_only: true` entspricht `opts: "ro"`.
      # Schreibversuche im Container → EROFS. Perfekt für
      # Konfigurationsdateien die der Admin von außen pflegt
      # (Deploy/CI schreibt, Container liest).
      volume "/etc/app", persist: "app-config",
                         read_only: true

      # ── /uploads — rw aber nicht ausführbar ─────────────
      #
      # Der zentrale Härtungstrick: der Container kann in
      # `/uploads` schreiben und lesen (rw), aber Linux lehnt
      # `execve` auf jeder Datei dort ab (noexec), ignoriert
      # SUID-Bits (nosuid) und Devices (nodev). Ein gehackter
      # Upload-Handler kann damit Dateien kippen, aber keinen
      # Code aus ihnen ausführen.
      #
      # relatime → atime wird nur bei ersten-Zugriff-pro-Tag
      # aktualisiert; spart writeback bei heavy read-Last.
      volume "/uploads", persist: "app-uploads",
                         opts: "rw,nosuid,nodev,noexec,relatime"

      # ── /cache — schneller rw Cache ─────────────────────
      #
      # Wie /data, aber mit atime-Writeback minimiert.
      # Für Template-Caches, kompilierte Assets, etc.
      volume "/cache", persist: "app-cache",
                       opts: "rw,nosuid,nodev,relatime"

      # ── /scratch — per-Run Scratch (ephemer) ────────────
      #
      # `ephemeral: true` → das Volume wird zerstört, sobald
      # der Container in `stopped` oder `failed` eintritt.
      # Host-Verzeichnis + Metadata-Eintrag verschwinden
      # sauber. Für temporäre Decompress-Areas, Per-Request-
      # Arbeitsdateien, Test-Fixtures.
      volume "/scratch", persist: "scratch",
                         opts: "rw,nosuid,nodev,noexec",
                         ephemeral: true

      publish interval: 2000 do
        metric :memory
        metric :cpu
      end

      stream retention: {7, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end
end
