defmodule ThreeTierNft do
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════
  # Three-Tier Web Architecture — nft-transparente DSL
  # ══════════════════════════════════════════════════════
  #
  # Jede Regel in dieser Datei entspricht 1:1 einer nft-Regel.
  # Keine versteckte Semantik, keine Auto-Generierung.
  # Siehe ADR-0015.
  #
  # Topologie:
  #
  #   Internet (:8443)
  #      │
  #   ┌──┴───────────────────────────────┐
  #   │  Bridge: dmz (10.0.0.0/24)      │
  #   │  Container: web-0-nginx          │
  #   │  Veth: vh.web0nginx              │
  #   │  Lauscht auf :8443 (HTTPS)       │
  #   └──┬───────────────────────────────┘
  #      │
  #   ┌──┴───────────────────────────────┐
  #   │  Bridge: app (10.0.1.0/24)      │
  #   │  Container: app-0-api            │
  #   │  Veth: vh.app0api                │
  #   │  Lauscht auf :4000 (API)         │
  #   └──┬───────────────────────────────┘
  #      │
  #   ┌──┴───────────────────────────────┐
  #   │  Bridge: data (10.0.2.0/24)     │
  #   │  Container: data-0-postgres      │
  #   │  Veth: vh.data0postgre           │
  #   │  Lauscht auf :5432 (PostgreSQL)  │
  #   └─────────────────────────────────┘
  #
  # Paketfluss (eingehend von Internet):
  #
  #   1. Paket an PUBLIC_IP:8443 kommt auf eth0 an
  #   2. Prerouting/raw (priority -300): Ban-Set Check
  #   3. Prerouting/dstnat (priority -100): DNAT schreibt
  #      Ziel-IP um: PUBLIC_IP:8443 → 10.0.0.2:8443 (nginx Container)
  #   4. Kernel-Routing: Paket geht in Forward-Chain (nicht Input)
  #   5. Forward-Chain (priority 0):
  #      - ct established? → ja bei Folgepaketen
  #      - Egress-Jump? → nein (kommt von eth0, nicht vom Container)
  #      - iifname eth0 + daddr 10.0.0.2 + dport 8443? → ACCEPT
  #   6. Paket wird an nginx via Bridge "dmz" + Veth zugestellt
  #
  # Paketfluss (Container → Container):
  #
  #   1. nginx sendet SYN an 10.0.1.2:4000 (api)
  #   2. Forward-Chain:
  #      - ct established? → nein (neues SYN)
  #      - iifname vh.web0nginx? → ja → JUMP "from-web-nginx"
  #        - Egress: tcp_dport 4000? → ACCEPT
  #      - saddr nginx + daddr api + dport 4000? → ACCEPT
  #   3. Paket wird an api via Bridge "app" + Veth zugestellt
  #
  # Monitoring über AMQP (erlkoenig.events exchange):
  #
  #   firewall.forward.drop            — Drops in der Forward-Chain (rate)
  #   firewall.from-web-nginx.drop    — Illegale Egress-Versuche vom Nginx
  #   firewall.from-app-api.drop      — Illegale Egress-Versuche von der API
  #   firewall.from-data-postgres.drop — Illegale Egress-Versuche von der DB
  #   firewall.forward.packet         — NFLOG mit Paket-Details bei Drops
  #   conntrack.flow.new / .destroy   — Conntrack (neue/beendete Verbindungen)
  #   stats.web-0-nginx.memory        — cgroup Memory Stats (alle 2s)
  #   stats.data-0-postgres.pressure  — PSI Pressure (alle 30s)
  #
  # Testen:
  #
  #   # Erlaubter Pfad: app → postgres:5432
  #   nsenter -t <app-pid> -n nc -zw1 10.0.2.2 5432   → OK
  #
  #   # Verbotener Pfad: app → postgres:1234
  #   nsenter -t <app-pid> -n nc -zw1 10.0.2.2 1234   → DROP
  #   → nft.counter.forward_drop zeigt Rate im Consumer
  #
  #   # Illegaler Egress: nginx versucht direkt zur DB
  #   nsenter -t <web-pid> -n nc -zw1 10.0.2.2 5432   → DROP
  #   → nft.counter.web_nginx_drop (Egress-Filter blockiert)

  host do
    interface "eth0", zone: :wan

    # Drei isolierte Bridges — eine pro Tier.
    # Jede Bridge ist ein eigenes Layer-2-Segment.
    # Traffic zwischen Bridges muss durch die Forward-Chain.
    bridge "dmz",  subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
    bridge "app",  subnet: {10, 0, 1, 0, 24}
    bridge "data", subnet: {10, 0, 2, 0, 24}

    # ── Host-Firewall ──────────────────────────────────
    #
    # Schützt den Host selbst (nicht die Container).
    # Nur SSH und established Traffic erlaubt.

    nft_table :inet, "host" do
      # Ban-Set: gebannte IPs werden in der Raw-Chain gedroppt
      # (priority -300) — VOR conntrack, null Kernel-State.
      nft_set "ban", :ipv4_addr
      nft_counter "input_drop"
      nft_counter "input_ban"

      # Raw: drop gebannte IPs vor conntrack (priority -300)
      base_chain "prerouting", hook: :prerouting, type: :filter,
        priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      base_chain "input",
        hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        # Antworten auf Verbindungen die der Host initiiert hat
        nft_rule :accept, ct_state: [:established, :related]

        # Loopback (localhost, epmd, Erlang Distribution)
        nft_rule :accept, iifname: "lo"

        # ICMP: Ping für Monitoring
        nft_rule :accept, ip_protocol: :icmp

        # SSH-Zugang
        nft_rule :accept, tcp_dport: 22

        # Prometheus Node-Exporter
        nft_rule :accept, tcp_dport: 9100

        # Alles andere loggen + zählen + droppen
        nft_rule :drop, counter: "input_drop", log_prefix: "HOST: "
      end
    end

    # ── Container-Firewall ─────────────────────────────
    #
    # Kontrolliert den gesamten Traffic zwischen Containern.
    # Zwei Ebenen:
    #
    #   1. Egress-Chains (from-*): Was darf ein Container senden?
    #      Betreten via: iifname "vh.<container>" jump from-<name>
    #      Wenn ein Paket vom Container-Veth kommt, wird geprüft
    #      ob der Container diesen Outbound-Traffic senden darf.
    #
    #   2. Forward-Regeln: Welcher Traffic zwischen Bridges ist erlaubt?
    #      Explizite ip saddr/daddr + tcp dport Regeln pro Pfad.
    #      {:replica_ips, ...} wird zur Deploy-Zeit in konkrete IPs expandiert.

    nft_table :inet, "erlkoenig" do

      # Ban-Set nicht nötig hier — die Raw-Prerouting-Chain in
      # der host-Tabelle droppt gebannte IPs bereits vor dem
      # Forward-Hook (priority -300 < priority 0).

      # Named Counters — Table-Level Objekte.
      # Werden in Regeln referenziert via counter: "name".
      # erlkoenig_nft_watch pollt sie periodisch und sendet
      # Rate-Events über AMQP wenn packets > 0.
      nft_counter "forward_drop"
      nft_counter "web_nginx_drop"
      nft_counter "app_api_drop"
      nft_counter "data_postgres_drop"

      # ── Forward-Chain ────────────────────────────────
      #
      # Base-Chain: am Netfilter Forward-Hook.
      # Policy drop: alles was keine Regel matcht wird verworfen.
      #
      # Reihenfolge ist wichtig — nft evaluiert top-to-bottom:
      #   1. ct established (Antworten durchlassen)
      #   2. Egress-Jumps (Container-Outbound prüfen)
      #   3. Ingress-Allows (erlaubte Pfade zwischen Tiers)
      #   4. Default drop + counter + log
      #
      # Ban-Set nicht hier — prerouting/raw droppt schon vorher.

      base_chain "forward",
        hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        # Schritt 1: Bestehende Verbindungen durchlassen.
        # Wenn ein TCP-Handshake einmal akzeptiert wurde,
        # fließen alle Folgepakete (ACK, PSH, FIN) hier durch.
        nft_rule :accept, ct_state: [:established, :related]

        # Schritt 2: Container-Egress prüfen.
        # Pakete die VON einem Container-Veth kommen werden
        # in die jeweilige Egress-Chain gejumpt.
        # {:veth_of, "pod", "container"} wird zur Deploy-Zeit
        # zum konkreten Veth-Namen expandiert (z.B. "vh.web0nginx").
        # Bei replicas > 1 werden mehrere Jump-Regeln erzeugt.
        nft_rule :jump, iifname: {:veth_of, "web", "nginx"}, to: "from-web-nginx"
        nft_rule :jump, iifname: {:veth_of, "app", "api"}, to: "from-app-api"
        nft_rule :jump, iifname: {:veth_of, "data", "postgres"}, to: "from-data-postgres"

        # Schritt 3: Erlaubte Pfade zwischen Tiers.
        # Nur explizit gelistete Kombinationen sind erlaubt.
        # {:replica_ips, ...} wird zur Deploy-Zeit expandiert.
        # Bei replicas > 1 entsteht ein kartesisches Produkt
        # (jede Quell-IP × jede Ziel-IP).

        # Internet → Nginx: nur HTTPS (:8443)
        nft_rule :accept,
          iifname: "eth0",
          ip_daddr: {:replica_ips, "web", "nginx"},
          tcp_dport: 8443

        # Nginx → API: nur API-Port (:4000)
        nft_rule :accept,
          ip_saddr: {:replica_ips, "web", "nginx"},
          ip_daddr: {:replica_ips, "app", "api"},
          tcp_dport: 4000

        # API → Postgres: nur DB-Port (:5432)
        nft_rule :accept,
          ip_saddr: {:replica_ips, "app", "api"},
          ip_daddr: {:replica_ips, "data", "postgres"},
          tcp_dport: 5432

        # DMZ-Container dürfen ins Internet (Updates, DNS, etc.)
        nft_rule :accept, iifname: "dmz", oifname: "eth0"

        # Schritt 4: Alles was bis hier nicht gematcht hat → drop.
        # Counter zählt Drops, Log schreibt Prefix für NFLOG.
        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end

      # ── Egress-Chains ────────────────────────────────
      #
      # Reguläre Chains (kein Hook, kein Policy).
      # Werden via "jump" aus der Forward-Chain betreten.
      # Am Chain-Ende ist implizit "return" (zurück zur Forward-Chain).
      # Aber wir droppen explizit + zählen — so sehen wir
      # illegale Egress-Versuche im Counter.
      #
      # Warum Egress und nicht Ingress?
      # Die Jump-Regel matcht auf iifname (= Input-Interface im
      # Forward-Kontext). Für Bridge-Forwarding ist iifname das
      # Interface von dem das Paket KOMMT — also das Container-Veth.
      # Das bedeutet: Diese Chain filtert was der Container SENDEN darf.
      # Eingehender Traffic zum Container wird über die Forward-Regeln
      # (Schritt 3) kontrolliert, nicht über diese Chains.

      # Nginx: darf nur zum API (:4000) senden.
      # Antworten auf eingehende HTTPS-Verbindungen (:8443)
      # gehen über ct established durch — keine extra Regel nötig.
      nft_chain "from-web-nginx" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 4000
        nft_rule :drop, counter: "web_nginx_drop"
      end

      # API: darf nur zur DB (:5432) senden.
      # Antworten auf eingehende API-Calls (:4000) gehen
      # über ct established.
      nft_chain "from-app-api" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 5432
        nft_rule :drop, counter: "app_api_drop"
      end

      # DB: darf NUR antworten. Kein aktiver Outbound.
      # Jeder Versuch der DB nach draußen zu senden wird
      # gedroppt und gezählt — ein Alarm-Signal.
      nft_chain "from-data-postgres" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "data_postgres_drop"
      end

      # ── NAT: DNAT (eingehend) ─────────────────────────
      #
      # Prerouting/DNAT: schreibt die Ziel-IP um.
      # Pakete an die PUBLIC_IP:8443 werden umgeschrieben auf
      # die Container-IP 10.0.0.2:8443 (nginx).
      # Ohne DNAT erreicht Internet-Traffic den Container nicht —
      # der Kernel denkt die Public IP gehört zum Host (input).
      #
      # Priority :dstnat (-100) — evaluiert vor :filter (0),
      # also vor der Forward-Chain. Wenn das Paket die Forward-Chain
      # erreicht, hat es bereits die Container-IP als Ziel.

      base_chain "prerouting_nat", hook: :prerouting, type: :nat,
        priority: :dstnat, policy: :accept do

        # Internet → Nginx: DNAT auf Container-IP
        # {:replica_ips, ...} expandiert zur Deploy-Zeit.
        # Bei replicas: 1 → eine DNAT Regel.
        # Bei replicas: 3 → braucht Loadbalancing (jhash, future).
        nft_rule :dnat,
          iifname: "eth0",
          tcp_dport: 8443,
          dnat_to: {:replica_ips, "web", "nginx", 8443}
      end

      # ── NAT: Masquerade (ausgehend) ─────────────────
      #
      # Masquerade: Container-Traffic der das Host-Interface
      # verlässt bekommt die Host-IP als Absender (SNAT).
      # Ohne das können Container nicht ins Internet.

      base_chain "postrouting",
        hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do

        # Container-Subnets → Masquerade wenn sie die Bridge verlassen
        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "dmz"
        nft_rule :masquerade, ip_saddr: {10, 0, 1, 0, 24}, oifname_ne: "app"
        nft_rule :masquerade, ip_saddr: {10, 0, 2, 0, 24}, oifname_ne: "data"

        # DMZ → Internet: explizite Masquerade-Regel
        nft_rule :masquerade, iifname: "dmz", oifname: "eth0"
      end
    end
  end

  # ══════════════════════════════════════════════════════
  # Container Templates
  # ══════════════════════════════════════════════════════
  #
  # Pods definieren NUR Container: Binary, Args, Limits.
  # Keine Firewall — die steht oben im nft_table Block.
  # Das ist der Kernunterschied zur alten DSL.

  pod "web", strategy: :one_for_one do
    container "nginx",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8443"],
      limits: %{memory: 268_435_456, pids: 100},
      seccomp: :default,
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      publish interval: 10_000 do
        metric :pressure
        metric :oom_events
      end

      stream retention: {30, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end

  pod "app", strategy: :one_for_one do
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      limits: %{memory: 536_870_912, pids: 200},
      seccomp: :default,
      restart: {:on_failure, 5} do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      stream retention: {90, :days} do
        channel :stderr
      end
    end
  end

  pod "data", strategy: :one_for_one do
    container "postgres",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5432"],
      limits: %{memory: 1_073_741_824, pids: 50},
      seccomp: :default,
      restart: :always do

      publish interval: 5000 do
        metric :memory
        metric :pids
      end

      publish interval: 30_000 do
        metric :pressure
        metric :oom_events
      end

      stream retention: {90, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end

  # ══════════════════════════════════════════════════════
  # Deployment
  # ══════════════════════════════════════════════════════
  #
  # attach verbindet Pods mit Bridges.
  # {:veth_of, ...} und {:replica_ips, ...} werden zur
  # Deploy-Zeit anhand der attach-Konfiguration expandiert.
  # Bei replicas: 2 entstehen pro Pod zwei Container-Instanzen
  # mit eigenen IPs und Veth-Paaren.

  attach "web",  to: "dmz",  replicas: 1
  attach "app",  to: "app",  replicas: 1
  attach "data", to: "data", replicas: 1
end
