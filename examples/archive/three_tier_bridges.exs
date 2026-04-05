defmodule ThreeTier do
  use Erlkoenig.Stack

  # ── Three-Tier Web Architecture ───────────────────────
  #
  # Drei isolierte Bridges, eine pro Tier:
  #
  #   Internet
  #      │ :8443
  #      ▼
  #   ┌──────────────────────────────┐
  #   │  dmz (10.0.0.0/24)          │
  #   │  web-0-nginx  :8443         │  ← öffentlich
  #   └──────────┬───────────────────┘
  #              │ :4000
  #   ┌──────────┴───────────────────┐
  #   │  app (10.0.1.0/24)          │
  #   │  app-0-api    :4000         │  ← intern
  #   └──────────┬───────────────────┘
  #              │ :5432
  #   ┌──────────┴───────────────────┐
  #   │  data (10.0.2.0/24)         │
  #   │  data-0-postgres :5432      │  ← isoliert
  #   └─────────────────────────────┘
  #
  # Firewall:
  #   - Forward-Chain kontrolliert welcher Traffic zwischen Bridges fließt
  #   - Per-Container inbound-Chain kontrolliert was der Container senden darf
  #   - Alles was keine Regel matcht wird gedroppt + gezählt (Named Counter)
  #
  # Events über AMQP:
  #   - container.started/stopped/restarting  ← Lifecycle
  #   - nft.ct.new/destroy                   ← Verbindungen
  #   - nft.counter.zone_dmz_drop            ← Drops in der Forward-Chain
  #   - nft.counter.web-0-nginx_drop         ← Drops in Container-Chains
  #
  # Testen:
  #   # Falscher Port → Drop wird gezählt:
  #   nsenter -t <app-pid> -n nc -zw1 10.0.0.2 9999
  #   → nft.counter.zone_dmz_drop zeigt Rate im Python Consumer

  host do
    interface "eth0", zone: :wan

    bridge "dmz",  subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
    bridge "app",  subnet: {10, 0, 1, 0, 24}
    bridge "data", subnet: {10, 0, 2, 0, 24}

    # Host-Firewall: nur SSH + established
    chain "input", hook: :input, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "lo"
      rule :accept, tcp: 22
      rule :drop, log: "HOST: "
    end

    # Forward-Chain: kontrolliert Traffic zwischen Bridges
    chain "forward", hook: :forward, policy: :drop do
      rule :accept, ct: :established

      # Internet → DMZ: nur HTTPS zum Webserver
      rule :accept, iif: "eth0", oif: "web.nginx", tcp: 8443

      # DMZ → App: Webserver darf zum API
      rule :accept, iif: "web.nginx", oif: "app.api", tcp: 4000

      # App → Data: API darf zur Datenbank
      rule :accept, iif: "app.api", oif: "data.postgres", tcp: 5432

      # DMZ → Internet: Container dürfen raus
      rule :accept, iif: "dmz", oif: "eth0"

      # Alles andere: drop + log
      rule :drop, log: "FWD: "
    end

    # NAT für ausgehenden Container-Traffic
    chain "postrouting", hook: :postrouting, type: :nat do
      rule :masquerade, iif: "dmz", oif: "eth0"
    end
  end

  # ── Web-Tier: Reverse Proxy ───────────────────────────
  # Akzeptiert HTTPS (:8443), darf zum API (:4000)

  pod "web" do
    container "nginx",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8443"] do
      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 8443
        rule :accept, tcp: 4000
        rule :drop
      end
    end
  end

  # ── App-Tier: API Server ──────────────────────────────
  # Akzeptiert API-Calls (:4000), darf zur DB (:5432)

  pod "app" do
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"] do
      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 4000
        rule :accept, tcp: 5432
        rule :drop
      end
    end
  end

  # ── Data-Tier: Datenbank ──────────────────────────────
  # Akzeptiert nur DB-Connections (:5432), kein Outbound

  pod "data" do
    container "postgres",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5432"] do
      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 5432
        rule :drop
      end
    end
  end

  attach "web",  to: "dmz",  replicas: 1
  attach "app",  to: "app",  replicas: 1
  attach "data", to: "data", replicas: 1
end
