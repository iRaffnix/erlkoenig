defmodule ThreeTier do
  use Erlkoenig.Stack

  # ── Three-Tier mit PID-Limits (Fork-Bomb-Schutz) ─────
  #
  # pids: 2 = hard kernel limit (init + app, nothing else).
  # Jeder Fork-Versuch scheitert am Kernel-Limit.
  # Nur der Worker bekommt pids: 50 (darf forken).
  #
  #   dmz  (10.0.1.0/24): proxy :8080    pids: 2
  #   app  (10.0.2.0/24): api :4000      pids: 2
  #                        worker :5000   pids: 50
  #   data (10.0.3.0/24): cache :6379    pids: 2

  host do
    interface "eth0", zone: :wan

    bridge "dmz",  subnet: {10, 0, 1, 0, 24}, uplink: "eth0"
    bridge "app",  subnet: {10, 0, 2, 0, 24}
    bridge "data", subnet: {10, 0, 3, 0, 24}

    nft_table :inet, "host" do
      base_chain "input",
        hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop
      end
    end

    nft_table :inet, "erlkoenig" do
      nft_counter "forward_drop"
      nft_counter "proxy_drop"
      nft_counter "api_drop"
      nft_counter "worker_drop"
      nft_counter "cache_drop"

      base_chain "forward",
        hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]

        nft_rule :jump, iifname: {:veth_of, "proxy", "proxy"}, to: "from-proxy"
        nft_rule :jump, iifname: {:veth_of, "app", "api"}, to: "from-api"
        nft_rule :jump, iifname: {:veth_of, "app", "worker"}, to: "from-worker"
        nft_rule :jump, iifname: {:veth_of, "cache", "cache"}, to: "from-cache"

        # Internet → Proxy
        nft_rule :accept,
          iifname: "eth0",
          ip_daddr: {:replica_ips, "proxy", "proxy"},
          tcp_dport: 8080

        # Proxy → API
        nft_rule :accept,
          ip_saddr: {:replica_ips, "proxy", "proxy"},
          ip_daddr: {:replica_ips, "app", "api"},
          tcp_dport: 4000

        # API → Cache
        nft_rule :accept,
          ip_saddr: {:replica_ips, "app", "api"},
          ip_daddr: {:replica_ips, "cache", "cache"},
          tcp_dport: 6379

        # DMZ darf raus
        nft_rule :accept, iifname: "dmz", oifname: "eth0"

        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end

      # Proxy: darf zum API (:4000)
      nft_chain "from-proxy" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 4000
        nft_rule :drop, counter: "proxy_drop"
      end

      # API: darf zum Cache (:6379)
      nft_chain "from-api" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 6379
        nft_rule :drop, counter: "api_drop"
      end

      # Worker: darf nur antworten
      nft_chain "from-worker" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "worker_drop"
      end

      # Cache: darf nur antworten
      nft_chain "from-cache" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "cache_drop"
      end

      base_chain "postrouting",
        hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do

        nft_rule :masquerade, ip_saddr: {10, 0, 1, 0, 24}, oifname_ne: "dmz"
        nft_rule :masquerade, ip_saddr: {10, 0, 2, 0, 24}, oifname_ne: "app"
        nft_rule :masquerade, ip_saddr: {10, 0, 3, 0, 24}, oifname_ne: "data"
        nft_rule :masquerade, iifname: "dmz", oifname: "eth0"
      end
    end
  end

  pod "proxy", strategy: :one_for_one do
    container "proxy",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      limits: %{memory: 268_435_456, pids: 2},
      restart: :always,
      health_check: [port: 8080, interval: 5000, retries: 3] do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end
  end

  pod "app", strategy: :one_for_all do
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      limits: %{memory: 536_870_912, pids: 2},
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

    container "worker",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5000"],
      limits: %{memory: 268_435_456, pids: 50},
      restart: :on_failure do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end
  end

  pod "cache", strategy: :one_for_one do
    container "cache",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["6379"],
      limits: %{memory: 134_217_728, pids: 2},
      restart: :always,
      health_check: [port: 6379, interval: 5000, retries: 5] do

      publish interval: 5000 do
        metric :memory
        metric :pids
      end
    end
  end

  attach "proxy", to: "dmz",  replicas: 1
  attach "app",   to: "app",  replicas: 1
  attach "cache", to: "data", replicas: 1
end
