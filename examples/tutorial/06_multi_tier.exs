defmodule Tutorial.MultiTier do
  @moduledoc """
  ### Datei 6/6 — Produktionsnahes Three-Tier-Setup

  Ein realistic-geformtes Stack: **Frontend → API → DB**. Demonstriert
  wie die ganzen Primitives aus 01-05 zusammen benutzt werden um
  einen echten workload zu betreiben.

  Struktur:

      [CDN/Internet]
            │
            ▼
       ┌────────┐      replicas: 3, pod strategy: one_for_one
       │ frontend│     jeder unabhängig skaliert, jhash-LB vor API
       └────┬───┘
            │  (internal)
            ▼
       ┌────────┐      replicas: 4, pod strategy: rest_for_one
       │  api   │     (api crasht → api + db-facing sidecars auch)
       └────┬───┘
            │  (db socket)
            ▼
       ┌────────┐      replicas: 1, pod strategy: one_for_all
       │   db   │     (im Pod mit seiner Backup-sidecar — crashen
       └────────┘      beide gemeinsam, starten gemeinsam)

  Pod-strategy-Beispiele hier decken alle drei cases ab.

  Features die zusammenkommen:
    - Replicas + replica-IP references via `{:replica_ips, pod, ct}`
    - jhash-DNAT load balancing (stable per-src-IP → backend mapping)
    - Pod-Supervisor-Strategien (one_for_one / rest_for_one / one_for_all)
    - Capabilities für journal/postgres/dns/dns.allowlist pro tier
    - Host-firewall die CDN-Edge und Internal-Traffic trennt
    - Per-Container nft für fine-grained tier-isolation

  ### Glasbox-Hinweis: WO lebt was?

  **Container-lokale nft** (`nft do input/output ... end`) kennt nur
  die eigene IP. Cross-container Refs wie `{:replica_ips, "backend",
  "api"}` sind dort architektonisch unmöglich — der Container-nft
  wird appliziert BEVOR andere Container ihre IPs haben, und läuft
  in einer isolierten netns. Versucht man es trotzdem, failt der
  Spawn mit `unresolvable_replica_ips_in_container_nft` (fail-loud,
  keine silent-weakening der Regel).

  **Host nft_table forward-chain** läuft auf der Host-netns, kennt
  alle Container-IPs, löst `{:replica_ips, ...}` beim Laden auf und
  expandiert zu einer Regel pro Replika-IP. Alle cross-tier rules
  gehören also hier hin.

  Daumenregel:
    * Container-nft    → Port-Whitelist + conn_limit + ICMP
    * Host forward     → wer-darf-zu-wem (IP-level)
    * Host input/output → externer Traffic (CDN / egress)
  """
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════════════
  # Host: zwei Zonen (public edge + internal)
  # ══════════════════════════════════════════════════════════════════
  host do
    # Public edge — frontend-Instanzen bekommen hier IPs
    ipvlan "edge", parent: {:dummy, "ek_edge"},
                   subnet: {10, 60, 0, 0, 24}

    # Internal — api + db, nicht vom Internet erreichbar
    ipvlan "internal", parent: {:dummy, "ek_internal"},
                       subnet: {10, 61, 0, 0, 24}

    nft_table :inet, "host" do
      nft_set "ban", :ipv4_addr
      nft_counter "input_drop"
      nft_counter "forward_drop"

      # jhash-target-map für load balancing auf die api-replicas.
      # Key = hash(src), Value = backend-IP. Consistent-hashing;
      # gleiche Source landet stabil auf gleichem Backend, bis
      # die Backend-Liste sich ändert.
      nft_map "api_backends", :inet_service, :ipv4_addr, []

      base_chain "prerouting_ban", hook: :prerouting, type: :filter,
                 priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban"
      end

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22

        # Public: HTTP + HTTPS direkt auf Host (würde in
        # Production zu einer LB-VIP routen; im Beispiel zum
        # Frontend-Pod).
        nft_rule :accept, tcp_dport: 80
        nft_rule :accept, tcp_dport: 443

        nft_rule :drop, counter: "input_drop", log_prefix: "HOST: "
      end

      # ── FORWARD chain — cross-container L4 policy ───────────────
      #
      # Hier wandert ALLES was "nur Container X → Container Y" heißt.
      # Die `{:replica_ips, Pod, Ct}` Tuples werden zum Load-Time auf
      # die tatsächlichen IPs expandiert (cartesian product → eine
      # Regel pro Replica-IP).
      base_chain "forward", hook: :forward, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, ip_protocol: :icmp

        # Frontend → API: HTTP nach :8080
        nft_rule :accept,
                 ip_saddr: {:replica_ips, "frontend", "nginx"},
                 ip_daddr: {:replica_ips, "backend", "api"},
                 tcp_dport: 8080

        # API → DB: Postgres-Socket-TCP :5432
        nft_rule :accept,
                 ip_saddr: {:replica_ips, "backend", "api"},
                 ip_daddr: {:replica_ips, "data", "postgres"},
                 tcp_dport: 5432

        # Backup-Sidecar → DB (im gleichen Pod, aber netns-separiert)
        nft_rule :accept,
                 ip_saddr: {:replica_ips, "data", "backup"},
                 ip_daddr: {:replica_ips, "data", "postgres"},
                 tcp_dport: 5432

        # Host (Metrics-Scraper) → Metrics-Sidecars :9100
        nft_rule :accept,
                 ip_saddr: {10, 61, 0, 1},
                 ip_daddr: {:replica_ips, "backend", "metrics"},
                 tcp_dport: 9100

        nft_rule :drop, counter: "forward_drop", log_prefix: "FWD: "
      end

      # ── Prerouting DNAT für jhash-LB ──
      # Jeder external Connect auf Port 443 wird per src-hash
      # auf eine der frontend-Replicas DNAT'd. Der nft_map
      # wird von erlkoenig automatisch mit den frontend-IPs
      # populated (replica-Adressen sind zur Laufzeit bekannt).
      base_chain "prerouting_nat", hook: :prerouting, type: :nat,
                 priority: :dstnat, policy: :accept do
        nft_rule :dnat_jhash,
          map: "api_backends",
          dport: 443,
          mod: 3         # mod = anzahl der backends im pool
      end
    end
  end

  # ══════════════════════════════════════════════════════════════════
  # POD 1: Frontend — stateless, horizontal skaliert
  # ══════════════════════════════════════════════════════════════════
  #
  # strategy: :one_for_one — jede Replica unabhängig. Crash einer
  # beeinflusst die anderen nicht. Klassisch für stateless workloads.
  pod "frontend", strategy: :one_for_one do

    container "nginx",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["443"],
      zone: "edge",
      replicas: 3,
      restart: :permanent,
      limits: %{memory: 128_000_000, pids: 64} do

      requires :"dns.local"
      requires :"journal.local"

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      stream retention: {7, :days} do
        channel :stdout
        channel :stderr
      end

      # Lokale Constraints nur — Ports, conn_limit, ICMP. Die
      # Cross-Container-Policy (welcher Peer darf zu wem) steht in
      # `host → forward`.
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, tcp_dport: 443
          conn_limit per_ip: 200
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_daddr: {10, 60, 0, 1}, udp_dport: 53
          nft_rule :accept, tcp_dport: 8080
        end
      end
    end
  end

  # ══════════════════════════════════════════════════════════════════
  # POD 2: Backend (API) — rest_for_one wegen sidecar-Reihenfolge
  # ══════════════════════════════════════════════════════════════════
  #
  # strategy: :rest_for_one — wenn der API-Container crasht, soll
  # auch das metrics-sidecar mit-restarten (weil es daran hängt).
  # Der api wird ZUERST in der Pod-Definition deklariert, dann das
  # metrics-sidecar. rest_for_one triggert für alle NACH dem
  # crashenden, in deklarations-Reihenfolge.
  pod "backend", strategy: :rest_for_one do

    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      zone: "internal",
      replicas: 4,
      restart: :permanent,
      limits: %{memory: 512_000_000, pids: 256} do

      # Kompletter capability-Stack
      requires :"dns.local"
      requires :"journal.local"
      requires :"postgres.local"

      # L7-Filter: API darf nur zu bekannten external APIs
      requires :"dns.allowlist", hosts: [
        "api.stripe.com",
        "*.s3.amazonaws.com"
      ]

      volume "/var/log/api", persist: "api-log"

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      publish interval: 10_000 do
        metric :pressure
        metric :oom_events
      end

      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, tcp_dport: 8080
          conn_limit per_ip: 500
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_daddr: {10, 61, 0, 1}, udp_dport: 53
          nft_rule :accept, tcp_dport: 443  # outbound TLS
          nft_rule :accept, tcp_dport: 5432 # zu DB
        end
      end
    end

    # Metrics-sidecar pro api-Replica. Läuft im gleichen pod →
    # gleiches Supervisor-Tree, rest_for_one-Semantik.
    container "metrics",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9100"],
      zone: "internal",
      replicas: 4,       # gleiche Anzahl wie api
      restart: :transient,
      limits: %{memory: 64_000_000, pids: 32} do

      requires :"dns.local"

      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, tcp_dport: 9100
        end
      end
    end
  end

  # ══════════════════════════════════════════════════════════════════
  # POD 3: Database — one_for_all, Backup eng gekoppelt
  # ══════════════════════════════════════════════════════════════════
  #
  # strategy: :one_for_all — crasht entweder db oder backup-sidecar,
  # restarten BEIDE gemeinsam. Rationale: das Backup-Tool hat
  # Session-State zur DB; wenn DB-Restart muss Backup auch neu
  # connecten. Klassische "sidecar gehört zum hauptcontainer".
  pod "data", strategy: :one_for_all do

    container "postgres",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5432"],
      zone: "internal",
      replicas: 1,                # DB einzeln (kein cluster hier)
      restart: :permanent,
      limits: %{memory: 2_000_000_000, pids: 512, disk: 10_000_000_000},
      signature: :required do    # Prod-DB-Binary immer signiert

      volume "/var/lib/postgresql/data", persist: "pgdata"
      volume "/etc/postgresql", persist: "pgetc", read_only: true

      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, tcp_dport: 5432
        end
      end
    end

    container "backup",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["backup"],
      zone: "internal",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 256_000_000, pids: 64} do

      requires :"journal.local"

      # Schreib-Volume für die dumps
      volume "/backups", persist: "pg-backups"
      # Ephemeral temp für WAL-staging
      volume "/tmp/wal", persist: "pg-wal-stage", ephemeral: true

      nft do
        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, tcp_dport: 5432
        end
      end
    end
  end

  # ══════════════════════════════════════════════════════════════════
  # Threat-Detection für den Edge-Tier
  # ══════════════════════════════════════════════════════════════════
  guard do
    detect do
      flood over: 100, within: s(10)
      port_scan over: 20, within: m(1)
      slow_scan over: 5, within: h(1)
      honeypot [21, 23, 445, 1433, 3389]
    end

    respond do
      suspect after: 3, distinct: :ports
      ban_for h(1)
      honeypot_ban_for h(24)
      escalate [h(1), h(6), h(24), d(7)]
      observe_after_unban m(2)
      forget_after m(5)
    end

    allowlist [
      {127, 0, 0, 1},
      {10, 60, 0, 1},   # edge zone gateway
      {10, 61, 0, 1}    # internal zone gateway
    ]
  end
end
