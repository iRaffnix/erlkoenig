defmodule MicroserviceCluster do
  use Erlkoenig.Stack

  # ── Microservice-Pattern: Gateway + interne Services ──
  #
  # DMZ:      gateway (1x) — Internet-facing reverse proxy
  # Internal: auth + api + db (1x) — Backend mit :rest_for_one
  #
  # Erlaubte Pfade:
  #   Internet → Gateway:8080/:8443
  #   Gateway → API:4000
  #   API → Auth:3000
  #   API → DB:5432

  host do
    interface "eth0", zone: :wan

    bridge "dmz",      subnet: {10, 0, 1, 0, 24}, uplink: "eth0"
    bridge "internal", subnet: {10, 0, 0, 0, 24}

    nft_table :inet, "host" do
      base_chain "input",
        hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop, log_prefix: "HOST: "
      end
    end

    nft_table :inet, "erlkoenig" do
      nft_counter "forward_drop"
      nft_counter "gateway_drop"
      nft_counter "auth_drop"
      nft_counter "api_drop"
      nft_counter "db_drop"

      base_chain "forward",
        hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]

        # Egress-Filter
        nft_rule :jump, iifname: {:veth_of, "gateway", "gw"}, to: "from-gateway"
        nft_rule :jump, iifname: {:veth_of, "services", "auth"}, to: "from-auth"
        nft_rule :jump, iifname: {:veth_of, "services", "api"}, to: "from-api"
        nft_rule :jump, iifname: {:veth_of, "services", "db"}, to: "from-db"

        # Internet → Gateway
        nft_rule :accept,
          iifname: "eth0",
          ip_daddr: {:replica_ips, "gateway", "gw"},
          tcp_dport: 8080

        nft_rule :accept,
          iifname: "eth0",
          ip_daddr: {:replica_ips, "gateway", "gw"},
          tcp_dport: 8443

        # Gateway → API
        nft_rule :accept,
          ip_saddr: {:replica_ips, "gateway", "gw"},
          ip_daddr: {:replica_ips, "services", "api"},
          tcp_dport: 4000

        # API → Auth
        nft_rule :accept,
          ip_saddr: {:replica_ips, "services", "api"},
          ip_daddr: {:replica_ips, "services", "auth"},
          tcp_dport: 3000

        # API → DB
        nft_rule :accept,
          ip_saddr: {:replica_ips, "services", "api"},
          ip_daddr: {:replica_ips, "services", "db"},
          tcp_dport: 5432

        # DMZ darf raus
        nft_rule :accept, iifname: "dmz", oifname: "eth0"

        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end

      # Gateway: darf zum API (:4000)
      nft_chain "from-gateway" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 4000
        nft_rule :drop, counter: "gateway_drop"
      end

      # Auth: darf nur antworten
      nft_chain "from-auth" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "auth_drop"
      end

      # API: darf zu Auth (:3000) und DB (:5432)
      nft_chain "from-api" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 3000
        nft_rule :accept, tcp_dport: 5432
        nft_rule :drop, counter: "api_drop"
      end

      # DB: darf nur antworten
      nft_chain "from-db" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "db_drop"
      end

      base_chain "postrouting",
        hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do

        nft_rule :masquerade, ip_saddr: {10, 0, 1, 0, 24}, oifname_ne: "dmz"
        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "internal"
        nft_rule :masquerade, iifname: "dmz", oifname: "eth0"
      end
    end
  end

  pod "gateway", strategy: :one_for_one do
    container "gw",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      limits: %{memory: 268_435_456},
      restart: :always,
      health_check: [port: 8080, interval: 5000, retries: 3] do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end
  end

  pod "services", strategy: :rest_for_one do
    container "auth",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      limits: %{memory: 134_217_728, pids: 50},
      seccomp: :default,
      restart: {:on_failure, 5},
      health_check: [port: 3000, interval: 10_000, retries: 3] do

      publish interval: 5000 do
        metric :memory
        metric :cpu
      end
    end

    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      limits: %{memory: 1_073_741_824, pids: 200},
      seccomp: :default,
      restart: {:on_failure, 5},
      health_check: [port: 4000, interval: 10_000, retries: 3] do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      publish interval: 10_000 do
        metric :pressure
        metric :oom_events
      end
    end

    container "db",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      limits: %{memory: 2_147_483_648, pids: 100},
      seccomp: :default,
      restart: :always,
      health_check: [port: 5432, interval: 5000, retries: 5] do

      publish interval: 5000 do
        metric :memory
        metric :pids
      end

      publish interval: 30_000 do
        metric :pressure
        metric :oom_events
      end
    end
  end

  attach "gateway",  to: "dmz",      replicas: 1
  attach "services", to: "internal", replicas: 1
end
