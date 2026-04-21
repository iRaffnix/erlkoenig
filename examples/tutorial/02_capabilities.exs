defmodule Tutorial.Capabilities do
  @moduledoc """
  ### Datei 2/6 — Service-Capabilities (`requires`)

  Jeder Container kann eine Liste von **Capabilities** deklarieren —
  Services die auf der Node laufen und vom Container genutzt werden
  sollen. Die Deklaration ist der Vertrag; der Runtime-Effekt ist
  sichtbar und an diese Deklaration gebunden.

  Glasbox-Prinzip: Die DSL-Zeile `requires :"journal.local"` löst
  GENAU die im Kapitel 19 des Buchs dokumentierten Mount + Env-Var
  Effekte aus. Keine Hidden Rules, kein Auto-Open von Ports. Wenn
  eine Capability Netzwerk braucht, schreibt der Operator die
  entsprechende nft-Regel selbst (siehe Datei 3).

  Heute verfügbar:

    * `:"dns.local"`        — node-scoped DNS-resolver auf Zone-GW
    * `:"dns.allowlist"`    — L7 DNS-filter (per-container hosts)
    * `:"journal.local"`    — tamper-evident audit-chain ingest
    * `:"postgres.local"`   — Unix-socket Postgres via peer-auth

  Pattern: `requires :capability` oder `requires :capability, opts`.
  Unknown caps → CompileError mit list of valid names.
  """
  use Erlkoenig.Stack

  host do
    ipvlan "caps", parent: {:dummy, "ek_caps"},
                   subnet: {10, 20, 0, 0, 24}

    # Damit `:"dns.local"` funktioniert muss der Container die
    # Zone-GW-IP auf UDP/53 erreichen. Die nft-Regel dafür schreibt
    # der Operator EXPLIZIT hin (kein Auto-Inject). Analog für
    # andere capabilities mit Netzwerk-Komponente.
    nft_table :inet, "host" do
      nft_counter "host_drop"

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22

        # Container-Zone darf zum DNS-Gateway. Pendant zu
        # `requires :"dns.local"` weiter unten.
        nft_rule :accept, ip_saddr: {10, 20, 0, 0, 24}, udp_dport: 53

        nft_rule :drop, counter: "host_drop"
      end
    end
  end

  pod "agents", strategy: :one_for_one do
    container "worker",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      zone: "caps",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 256_000_000, pids: 128} do

      # ════════════════════════════════════════════════════════════
      # Capability 1: DNS-Resolver (Node-lokal pro Zone)
      # ════════════════════════════════════════════════════════════
      #
      # Was:   pro-Zone gen_server der UDP/53 bedient
      # Wann:  jeder Workload der Namen auflösen muss
      # Wieso: Normaler Glibc-Resolver. Inbound-Container setzen
      #        /etc/resolv.conf automatisch auf die Zone-GW-IP.
      # Effekt: KEINE Mount/Env-Injection. Nur Dokumentation der
      #         Abhängigkeit + runtime-Hook der DNS_IP ins TLV des
      #         C-Runtime schreibt.
      requires :"dns.local"

      # ════════════════════════════════════════════════════════════
      # Capability 2: DNS-Allowlist (L7 Egress Filter)
      # ════════════════════════════════════════════════════════════
      #
      # Was:   SPEC-AS-009 L7-Half. Der Zone-DNS filtert Lookups
      #        pro Container: nur matching Hosts werden resolved,
      #        andere kriegen NXDOMAIN + signed audit-event.
      # Wann:  wenn Workload untrusted code laufen lässt (Agenten,
      #        customer binaries) — eine der stärksten L7-Guards.
      # Wieso: Name-Layer-Allowlisting. Selbst wenn der Container
      #        beliebigen Code ausführt, kann er nur zu den Hosts
      #        connecten deren Namen er auflösen darf.
      # Effekt: erlkoenig_dns_filter registriert die Liste gegen
      #         die Container-IP. Inbound-Queries von dieser IP
      #         werden gefiltert. Operator muss die L4-egress-
      #         Regel für TCP/443 zusätzlich explizit öffnen — der
      #         Filter schneidet Namen NICHT Ports.
      requires :"dns.allowlist", hosts: [
        "api.openai.com",
        "*.s3.amazonaws.com",
        "registry.npmjs.org",
        # Wildcard-Syntax: `*.example` matched genau eine Labels-
        # Ebene oder mehr (`foo.example`, `foo.bar.example`), NICHT
        # das nackte `example`.
      ]

      # ════════════════════════════════════════════════════════════
      # Capability 3: Journal (tamper-evident audit-chain ingest)
      # ════════════════════════════════════════════════════════════
      #
      # Was:   Unix-socket wo der Container structured log events
      #        reinkippt. Jedes Event landet in der daily-sealed
      #        hash-chain (SPEC-AS-005).
      # Wann:  jeder compliance-relevante Workload. Finanzkram,
      #        Gesundheitsdaten, jede Audit-Pflicht.
      # Wieso: Tamper-evident ohne dass der Container selbst
      #        Crypto machen muss — die Chain ist node-scoped, der
      #        Go-Verifier (Buch-Kapitel 20) prüft sie offline.
      # Effekt: Bind-mount `/run/erlkoenig/` ins Container, env
      #         `JOURNAL_LOCAL_SOCK=/run/erlkoenig/journal.sock`.
      #         Container schreibt JSON-lines rein, erlkoenig
      #         leitet an audit-module weiter.
      requires :"journal.local"

      # ════════════════════════════════════════════════════════════
      # Capability 4: Postgres (Unix-socket mit peer-auth)
      # ════════════════════════════════════════════════════════════
      #
      # Was:   Host-lokaler Postgres reachable via Unix-socket
      # Wann:  full-stack workloads (web-app mit DB)
      # Wieso: KEIN Password, KEIN TLS, KEIN Connection-String —
      #        peer-auth über bind-mounted socket ist die
      #        Authentifizierung. Der Container läuft als uid,
      #        der uid mapped in pg_ident auf eine role. Fertig.
      # Effekt: Bind-mount `/run/erlkoenig/` (dedupt mit journal),
      #         env `PGHOST=/run/erlkoenig` (directory-Form für
      #         libpq — libpq findet `.s.PGSQL.5432` darin selbst).
      requires :"postgres.local"

      # Noch mehr env kann der Operator setzen — coexistiert mit
      # den capability-injizierten Werten.
      #
      # env %{"LOG_LEVEL" => "info", "SHUTDOWN_GRACE_SEC" => "10"}

      # ────────────────────────────────────────────────────────
      # Container-Firewall. capabilities injizieren KEINE nft-
      # regeln — die L4-Policy ist explizit. Was das
      # `requires :"postgres.local"` effektiv erlaubt (Unix-socket
      # Access) geht NICHT über's Netzwerk, braucht also keine
      # nft-Regel. Was das `requires :"dns.local"` braucht (UDP/53
      # zur Zone-GW) steht hier.
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          # HTTP-API nach draußen öffnen — damit jemand den agent
          # anspricht.
          nft_rule :accept, tcp_dport: 8080
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp

          # DNS zur Zone-GW — sonst keine Namensauflösung.
          nft_rule :accept, ip_daddr: {10, 20, 0, 1}, udp_dport: 53

          # Egress nach TLS/443 — damit das Zeug die Hosts aus der
          # allowlist auch erreichen kann. `dns.allowlist` filtert
          # NAMEN; hier wird die TCP-Layer-Erlaubnis gesetzt. Beide
          # Layer zusammen = der Container kann exakt die erlaubten
          # Hosts auf Port 443 sprechen.
          nft_rule :accept, tcp_dport: 443
        end
      end
    end
  end
end
