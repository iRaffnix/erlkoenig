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
  #   Internet (:8443, Port 22 is honeypot trap)
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
  #   guard.threat.honeypot           — Instant ban on honeypot port probe
  #   guard.threat.slow_scan          — Slow scanner detected (5+ ports/hour)
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

        # SSH-Zugang (non-standard port, 22 is honeypot)
        nft_rule :accept, tcp_dport: 22222

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

      # ── Table-Level Objekte ──────────────────────────
      nft_counter "forward_drop"
      nft_counter "web_nginx_drop"
      nft_counter "app_api_drop"
      nft_counter "data_postgres_drop"

      # ════════════════════════════════════════════════════
      # Chains geordnet nach Kernel-Evaluierungsreihenfolge:
      #
      #   Priority -100  prerouting/dstnat  (DNAT)
      #   Priority   0   forward/filter     (Firewall)
      #                   + Egress-Chains    (Jump-Targets)
      #   Priority +100  postrouting/srcnat  (Masquerade)
      #
      # Ban-Set (-300) ist in der host-Tabelle.
      # ════════════════════════════════════════════════════

      # ── 1. jhash Loadbalancing Map ─────────────────
      #
      # Explizite Data Map: Jenkins Hash Result → Container-IP.
      # Der Entwickler sieht die Map, benennt sie, kontrolliert die Eintraege.
      # {:replica_ips, "web", "nginx"} wird zur Deploy-Zeit in die
      # tatsaechlichen Container-IPs expandiert (z.B. 10.0.0.2, 10.0.0.3, 10.0.0.4).

      nft_map "web_jhash", :mark, :ipv4_addr,
        entries: {:replica_ips, "web", "nginx"}

      # ── 2. DNAT: priority -100 ──────────────────────
      #
      # Schreibt die Ziel-IP um BEVOR das Routing entscheidet.
      # jhash(ip saddr) mod 3 → Lookup in web_jhash Map → DNAT.
      # Gleiche Source-IP → immer gleicher Container (sticky).
      # mod: 3 = Anzahl der Replicas — muss explizit angegeben werden.

      base_chain "prerouting_nat", hook: :prerouting, type: :nat,
        priority: :dstnat, policy: :accept do

        nft_rule :dnat_jhash,
          iifname: "eth0",
          tcp_dport: 8443,
          map: "web_jhash",
          mod: 3,
          port: 8443
      end

      # ── 2. Egress-Chains: Jump-Targets ──────────────
      #
      # Reguläre Chains (kein Hook, kein Policy).
      # Werden via :jump aus der Forward-Chain betreten.
      # Filtern was ein Container SENDEN darf.
      # Am Ende: expliziter Drop + Counter (kein return).

      # Nginx: darf nur zum API (:4000)
      nft_chain "from-web-nginx" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 4000
        nft_rule :drop, counter: "web_nginx_drop"
      end

      # API: darf nur zur DB (:5432)
      nft_chain "from-app-api" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 5432
        nft_rule :drop, counter: "app_api_drop"
      end

      # DB: darf NUR antworten — jeder aktive Outbound ist Alarm
      nft_chain "from-data-postgres" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "data_postgres_drop"
      end

      # ── 3. Forward: priority 0 ──────────────────────
      #
      # Evaluiert NACH DNAT — Pakete haben bereits die
      # Container-IP als Ziel.

      # ── Forward-Policy als Concat Verdict Map ─────
      #
      # Statt 7 einzelner accept Rules: ein O(1) Hashtable-Lookup.
      # ip saddr . ip daddr . tcp dport → accept
      # Jeder Pfad ist ein expliziter Eintrag.
      # Bei Autoscaling: neuer Container = neues Entry, kein Rule-Rebuild.

      nft_vmap "fwd_policy",
        fields: [:ipv4_addr, :ipv4_addr, :inet_service],
        entries: [
          # web → app:4000
          {{10, 0, 0, 2}, {10, 0, 1, 2}, 4000, :accept},
          {{10, 0, 0, 3}, {10, 0, 1, 2}, 4000, :accept},
          {{10, 0, 0, 4}, {10, 0, 1, 2}, 4000, :accept},
          # app → data:5432
          {{10, 0, 1, 2}, {10, 0, 2, 2}, 5432, :accept}
        ]

      base_chain "forward",
        hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        # Bestehende Verbindungen durchlassen
        nft_rule :accept, ct_state: [:established, :related]

        # Egress-Prüfung: was darf der Container senden?
        nft_rule :jump, iifname: {:veth_of, "web", "nginx"}, to: "from-web-nginx"
        nft_rule :jump, iifname: {:veth_of, "app", "api"}, to: "from-app-api"
        nft_rule :jump, iifname: {:veth_of, "data", "postgres"}, to: "from-data-postgres"

        # Internet → Nginx (nach DNAT: daddr ist Container-IP)
        nft_rule :accept,
          iifname: "eth0",
          ip_daddr: {:replica_ips, "web", "nginx"},
          tcp_dport: 8443

        # Container-zu-Container Policy: O(1) Lookup
        nft_rule :vmap_lookup, vmap: "fwd_policy"

        # DMZ → Internet (Updates, DNS)
        nft_rule :accept, iifname: "dmz", oifname: "eth0"

        # Default Drop
        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end

      # ── 4. Masquerade: priority +100 ────────────────
      #
      # SNAT: Container-Traffic bekommt die Host-IP als
      # Absender wenn es das Host-Interface verlässt.

      base_chain "postrouting",
        hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do

        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "dmz"
        nft_rule :masquerade, ip_saddr: {10, 0, 1, 0, 24}, oifname_ne: "app"
        nft_rule :masquerade, ip_saddr: {10, 0, 2, 0, 24}, oifname_ne: "data"
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

  # ══════════════════════════════════════════════════════
  # Threat Detection (ct_guard)
  # ══════════════════════════════════════════════════════
  #
  # Automatische Erkennung und Abwehr von Angriffen.
  # Keine impliziten Defaults — ohne diesen Block laeuft
  # kein Guard. Der Entwickler entscheidet jede Schwelle.
  #
  # ct_guard abonniert Conntrack-Events vom Kernel und
  # prueft jede neue Verbindung gegen die konfigurierten
  # Detektoren. Bei Schwellwert-Ueberschreitung wird die
  # Quell-IP in ein nft-Set eingetragen und in der
  # prerouting_ban Chain (priority -300, raw) gedroppt.
  #
  # Erkennungsschichten (von schnell nach langsam):
  #
  #   ┌─ Honeypot ──────────────────────────────────┐
  #   │ 1 Probe auf ungenutzten Port = sofort Ban   │
  #   │ Zero tolerance, zero false positives        │
  #   │ Port 22 ist Falle (SSH auf 22222)           │
  #   └─────────────────────────────────────────────┘
  #
  #   ┌─ Flood Detection ──────────────────────────┐
  #   │ >50 Connections in 10s von einer IP         │
  #   │ Faengt SYN-Floods, HTTP-Floods, Brute Force│
  #   └─────────────────────────────────────────────┘
  #
  #   ┌─ Port Scan ─────────────────────────────────┐
  #   │ >20 verschiedene Ports in 60s               │
  #   │ Faengt Nmap, Masscan, Zmap                  │
  #   └─────────────────────────────────────────────┘
  #
  #   ┌─ Slow Scan ─────────────────────────────────┐
  #   │ >5 verschiedene Ports in 1 Stunde           │
  #   │ Faengt Shodan, Censys, manuelle Recon       │
  #   │ (1 Port alle 10 Min umgeht fast alles)      │
  #   └─────────────────────────────────────────────┘
  #
  # Repeat Offender: IP wird zum N-ten Mal gebannt?
  # Eskalation: 1h → 6h → 24h → 7 Tage.
  #
  # AMQP Events (alle auf erlkoenig.events exchange):
  #
  #   guard.threat.ban              — Flood oder Port Scan
  #   guard.threat.honeypot         — Honeypot Port getroffen
  #   guard.threat.slow_scan        — Langsamer Scanner erkannt
  #   guard.threat.unban            — Ban abgelaufen

  guard do
    # ── Detektoren ────────────────────────────────
    #
    # Jeder Detektor ueberwacht Conntrack-Events fuer ein
    # bestimmtes Muster. threshold = max Events, window = Sekunden.

    detect :conn_flood, threshold: 50, window: 10
    # 50 neue Verbindungen in 10 Sekunden von einer IP.
    # Typisch: SYN-Flood (10.000+ SYN/s), HTTP-Flood,
    # SSH Brute Force (hydra, medusa).

    detect :port_scan, threshold: 20, window: 60
    # 20 verschiedene Ziel-Ports in 60 Sekunden.
    # Typisch: nmap -sS (SYN Scan), masscan,
    # zmap mit Port-Liste.

    detect :slow_scan, threshold: 5, window: 3600
    # 5 verschiedene Ports in 1 Stunde.
    # Faengt Angreifer die unter den schnellen Schwellen
    # bleiben: 1 Port alle 10 Minuten, ueber Stunden.
    # Shodan und Censys scannen so.

    # ── Honeypot Ports ────────────────────────────
    #
    # Ports die kein Service auf diesem Host nutzt.
    # JEDE einzelne Connection = sofortiger Ban.
    # Null False Positives: wer Port 23 (Telnet) probt
    # auf einem Server der kein Telnet hat, ist ein Scanner.
    #
    # Port 22 ist hier dabei weil SSH auf 22222 laeuft.
    # Alle Bots die Standard-Port 22 scannen werden
    # sofort fuer 24h gebannt.
    #
    # WICHTIG: Ports die tatsaechlich genutzt werden
    # (22222, 8443, 4000, 5432, 9100) duerfen NICHT
    # in dieser Liste stehen!

    honeypot_ports [
      21,     # FTP — niemand nutzt FTP in 2026
      22,     # SSH — laeuft auf 22222, Standard-Port ist Falle
      23,     # Telnet — archaisch, nur Scanner
      445,    # SMB — Windows File Sharing, nicht auf Linux
      1433,   # MSSQL — kein Microsoft SQL hier
      1521,   # Oracle DB — kein Oracle hier
      3306,   # MySQL — wir nutzen Postgres, nicht MySQL
      3389,   # RDP — Remote Desktop, nicht auf Linux
      5900,   # VNC — kein VNC hier
      6379,   # Redis — kein Redis hier
      8080,   # HTTP alt — kein Service auf 8080
      8888,   # HTTP alt — kein Service auf 8888
      9200,   # Elasticsearch — kein ES hier
      27017   # MongoDB — kein Mongo hier
    ]

    # Honeypot-Bans dauern laenger (24h) weil gezieltes
    # Probing auf nicht-existierende Dienste ein starkes
    # Signal ist. Regulaere Bans (Flood/Scan) sind 1h.
    honeypot_ban_duration 86400

    # ── Repeat Offender ───────────────────────────
    #
    # Eskalierendes Ban-System: wer wiederholt gebannt
    # wird, bekommt exponentiell laengere Sperren.
    #
    #   1. Ban:  1 Stunde     (3600s)
    #   2. Ban:  6 Stunden    (21600s)
    #   3. Ban:  24 Stunden   (86400s)
    #   4+ Ban:  7 Tage       (604800s)
    #
    # Die Eskalation gilt pro IP ueber die gesamte
    # Lebensdauer des erlkoenig-Prozesses.

    escalation [3600, 21600, 86400, 604800]

    # ── Basis Ban-Dauer ───────────────────────────
    #
    # Default fuer Flood und Port Scan (vor Eskalation).
    # Honeypot-Bans haben ihre eigene Dauer (oben).

    ban_duration 3600

    # ── Whitelist ─────────────────────────────────
    #
    # IPs die nie gebannt werden, egal was sie tun.
    # Wichtig: Management-IPs und Monitoring hier eintragen,
    # sonst sperrt sich der Admin selbst aus.

    whitelist {127, 0, 0, 1}       # localhost
    whitelist {10, 0, 0, 1}        # Bridge Gateway
  end

  attach "web",  to: "dmz",  replicas: 3
  attach "app",  to: "app",  replicas: 1
  attach "data", to: "data", replicas: 1
end
