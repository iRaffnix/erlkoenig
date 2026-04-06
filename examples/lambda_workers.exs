defmodule LambdaWorkers do
  use Erlkoenig.Stack

  # ── Lambda-Pattern: Gateway + N stateless Worker ──────
  #
  # Gateway (1x) nimmt HTTPS an, dispatcht an Worker-Pool.
  # Worker (5x) sind identisch, stateless, austauschbar.
  #
  # Firewall:
  #   - Internet → Gateway:8443 erlaubt
  #   - Gateway → Worker:9000 erlaubt (Dispatch)
  #   - Worker untereinander: verboten
  #   - Worker → Gateway: verboten (kein Rückkanal nötig)
  #
  # {:replica_ips, "worker", "fn"} expandiert bei replicas: 5
  # zu 5 IP-Adressen → 5 accept-Regeln im Forward.

  host do
    interface "eth0", zone: :wan

    bridge "edge",    subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
    bridge "compute", subnet: {10, 0, 1, 0, 24}

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
      nft_counter "worker_drop"

      base_chain "forward",
        hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]

        # Egress-Filter
        nft_rule :jump, iifname: {:veth_of, "gateway", "proxy"}, to: "from-gateway"
        nft_rule :jump, iifname: {:veth_of, "worker", "fn"}, to: "from-worker"

        # Internet → Gateway: nur HTTPS
        nft_rule :accept,
          iifname: "eth0",
          ip_daddr: {:replica_ips, "gateway", "proxy"},
          tcp_dport: 8443

        # Gateway → Worker: Dispatch auf :9000
        nft_rule :accept,
          ip_saddr: {:replica_ips, "gateway", "proxy"},
          ip_daddr: {:replica_ips, "worker", "fn"},
          tcp_dport: 9000

        # Edge darf raus
        nft_rule :accept, iifname: "edge", oifname: "eth0"

        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end

      # Gateway: darf zu Workern auf :9000
      nft_chain "from-gateway" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 9000
        nft_rule :drop, counter: "gateway_drop"
      end

      # Worker: darf nur antworten
      nft_chain "from-worker" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "worker_drop"
      end

      base_chain "postrouting",
        hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do

        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "edge"
        nft_rule :masquerade, ip_saddr: {10, 0, 1, 0, 24}, oifname_ne: "compute"
        nft_rule :masquerade, iifname: "edge", oifname: "eth0"
      end
    end
  end

  pod "gateway", strategy: :one_for_one do
    container "proxy",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8443"],
      limits: %{memory: 268_435_456, pids: 100},
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end
  end

  pod "worker", strategy: :one_for_one do
    container "fn",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9000"],
      limits: %{memory: 134_217_728, pids: 50},
      restart: {:on_failure, 3} do

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
  end

  attach "gateway", to: "edge",    replicas: 1
  attach "worker",  to: "compute", replicas: 5
end
