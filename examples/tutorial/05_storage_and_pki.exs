defmodule Tutorial.StorageAndPki do
  @moduledoc """
  ### Datei 5/6 — Storage + PKI (SPEC-EK-024, SPEC-EK-017)

  Zwei Dinge die ein production-Container braucht: persistenten
  Zustand und verified Binaries.

  ### Storage

  erlkoenig verwaltet alle Volumes zentral unter
  `/var/lib/erlkoenig/volumes/<uuid>/`. Die DSL nennt nur einen
  **persist-Name**; die UUID-Zuordnung lebt im volume-store
  (persistent_term + erlkoenig_volume_store ETS).

  Formen:
    * persistent — überlebt Container-restart, UUID gleich
    * ephemeral  — wird bei `stopped` entsorgt (für tmpfs-style)
    * read_only  — Container sieht den Mount read-only

  Mount-Optionen wie `nosuid,nodev,noexec` sind NICHT dekorativ —
  der XFS-on-loop Stack (SPEC-EK-024) enforced sie strict.

  ### PKI

  Container können signed binaries verlangen. Die Kette:
    1. Binary mit Detached-Signature (sig-File daneben)
    2. Trust-Root in `/etc/erlkoenig/trust/*.pem`
    3. DSL sagt `signature: :required` oder expliziten Pfad
    4. Runtime verifies VOR spawn — Mismatch → spawn-failure mit
       signed `pki_verify_failed` audit event

  Kombiniert mit `files:` (injected file contents) und
  `rootfs:` (composefs manifest) gibt's attestable container
  provenance — lohnt für regulated workloads.

  This runnable tutorial keeps PKI as an operator note only: the installed
  demo binaries are intentionally unsigned. The fail-closed deployment
  shape lives in `examples/stacks/signed_deployment.exs` and Chapter 10.
  """
  use Erlkoenig.Stack

  host do
    ipvlan "data", parent: {:dummy, "ek_data"},
                   subnet: {10, 50, 0, 0, 24}

    nft_host do
      nft_counter "input_drop"
      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop, counter: "input_drop"
      end
    end
  end

  pod "stateful", strategy: :one_for_one do

    # ══════════════════════════════════════════════════════════════
    # Container 1: postgres mit persistenten Volumes
    # ══════════════════════════════════════════════════════════════
    container "db",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5432"],
      zone: "data",
      replicas: 1,
      restart: :temporary,
      limits: %{memory: 512_000_000, pids: 256},
      # ── Signed Binary ──
      # In production this DB binary would use:
      #   signature: :required
      # The runnable tutorial omits it because the shipped echo_server
      # demo binary is unsigned.
      # ── Injected Files ──
      # Kleine Konfigs die der Container lesen soll, werden
      # inline injiziert statt in einem Volume zu leben. Kernel
      # kriegt die Contents, legt sie als read-only bind-mount
      # rein. Gut für TLS-Certs, Policy-Dateien, License-Keys.
      files: %{
        "/etc/db/tls.crt" => "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
        "/etc/db/config.toml" => """
        log_level = "info"
        max_connections = 100
        """
      } do

      # ── PERSISTENT VOLUME ──
      # Was:   bind-mount von /var/lib/erlkoenig/volumes/<uuid>/
      # Wann:  echte Daten die Container-restart überleben müssen
      # Wieso: Der `persist:`-Name ist stable. Bei restart wird
      #        das GLEICHE UUID-dir remounted. Der operator kann
      #        snapshots des UUID-dir machen (xfs_quota + reflink
      #        clone — siehe Kapitel 15).
      volume "/var/lib/postgresql/data",
             persist: "postgres-data"

      # ── READ-ONLY PERSISTENT VOLUME ──
      # Für Config-Dateien die zwar persistent sein müssen (über
      # Restarts stabil), aber vom Container nicht schreibbar —
      # Angreifer mit container-rw kann Config nicht manipulieren.
      volume "/etc/postgresql",
             persist: "postgres-etc",
             read_only: true

      # ── MOUNT-OPTIONS ──
      # Volle Mount-Flags wie bei der mount(8). Werden vom
      # erlkoenig_mount_opts Validator gegen die XFS-Realität
      # geprüft. nosuid+nodev+noexec ist guter Default für
      # Daten-dirs — ein Angreifer der Schreibzugriff kriegt
      # kann keine setuid-Binaries ablegen.
      volume "/srv/import",
             persist: "postgres-ingest",
             opts: "rw,nosuid,nodev,noexec,relatime"

      # ── EPHEMERAL VOLUME ──
      # Wird bei stopped(enter) gelöscht, UUID geht weg. Guter
      # Ersatz für `/tmp` wenn das bind-mount getrennt sein soll.
      volume "/tmp",
             persist: "postgres-tmp",
             ephemeral: true

      # Container-lokale nft: nur Port-Whitelist + ct_state.
      # Die "wer darf zu wem"-Policy (cross-container IP-match) kommt
      # in die host forward-chain (siehe Tutorial 06 Glasbox-Hinweis):
      # container-nft kennt keine anderen Container-IPs. Hier reicht
      # uns tcp_dport 5432 open — Zone-Isolation (ipvlan) stellt sicher
      # dass nur Container derselben Zone "data" überhaupt verbinden.
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, tcp_dport: 5432
        end
      end
    end

    # ══════════════════════════════════════════════════════════════
    # Container 2: API — cgroup-heavy
    # ══════════════════════════════════════════════════════════════
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      zone: "data",
      replicas: 2,                           # zwei Instanzen
      # Signature verification failures need PKI setup, not a retry loop.
      restart: :temporary,
      limits: %{
        memory: 256_000_000,                 # 256 MB hard cap
        pids:   128,
        cpu:    50_000,                      # 50% einer CPU-unit
        disk:   1_000_000_000                # 1 GB volume budget
      }
      # In production this API binary could use an explicit detached
      # signature path, for example:
      #   signature: "/etc/erlkoenig/artifacts/api.sig"
      # The runnable tutorial omits it for the unsigned demo binary.
      do

      requires :"postgres.local"
      requires :"journal.local"
      requires :"dns.local"

      # ── Shared-log-Volume zwischen allen Replicas ──
      # Jede Replica bind-mounted dieselbe persist-path. Gut für
      # zentrale Log-Aggregation; schlecht wenn die Replicas
      # gleichzeitig in dieselbe Datei schreiben ohne Locking.
      volume "/var/log/api", persist: "api-logs"

      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, tcp_dport: 8080
          conn_limit per_ip: 200
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_daddr: {10, 50, 0, 1}, udp_dport: 53
          # zu den db-Replicas geht nur via tcp/5432 — keine IP-Constraint
          # hier, die kommt als replica_ips-ref ins host-Forward-chain
          nft_rule :accept, tcp_dport: 5432
        end
      end
    end
  end
end
