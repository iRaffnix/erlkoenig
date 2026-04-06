defmodule PodFirewall do
  use Erlkoenig.Stack

  # ── Pod mit Frontend + API auf einer Bridge ───────────
  #
  # Zwei Interfaces: eth0 (WAN) + eth1 (LAN).
  # Frontend erreichbar von WAN (:8080).
  # API erreichbar von LAN (:4000) und vom Frontend.
  #
  # Egress: Frontend darf nur zum API (:4000).
  #         API darf nur antworten.

  host do
    interface "eth0", zone: :wan
    interface "eth1", zone: :lan
    bridge "br0", subnet: {10, 0, 0, 0, 24}, uplink: "eth0"

    nft_table :inet, "host" do
      base_chain "input",
        hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, iifname: "eth1"
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop, log_prefix: "HOST_DROP: "
      end
    end

    nft_table :inet, "erlkoenig" do
      nft_counter "forward_drop"
      nft_counter "frontend_drop"
      nft_counter "api_drop"

      base_chain "forward",
        hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]

        nft_rule :jump, iifname: {:veth_of, "web", "frontend"}, to: "from-frontend"
        nft_rule :jump, iifname: {:veth_of, "web", "api"}, to: "from-api"

        # WAN → Frontend :8080
        nft_rule :accept,
          iifname: "eth0",
          ip_daddr: {:replica_ips, "web", "frontend"},
          tcp_dport: 8080

        # LAN → API :4000
        nft_rule :accept,
          iifname: "eth1",
          ip_daddr: {:replica_ips, "web", "api"},
          tcp_dport: 4000

        # Frontend → API :4000
        nft_rule :accept,
          ip_saddr: {:replica_ips, "web", "frontend"},
          ip_daddr: {:replica_ips, "web", "api"},
          tcp_dport: 4000

        nft_rule :accept, iifname: "br0", oifname: "eth0"
        nft_rule :drop, log_prefix: "FWD_DROP: ", counter: "forward_drop"
      end

      # Frontend: darf zum API (:4000)
      nft_chain "from-frontend" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 4000
        nft_rule :drop, counter: "frontend_drop"
      end

      # API: darf nur antworten
      nft_chain "from-api" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "api_drop"
      end

      base_chain "postrouting",
        hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do

        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "br0"
        nft_rule :masquerade, iifname: "br0", oifname: "eth0"
      end
    end
  end

  pod "web", strategy: :one_for_all do
    container "frontend",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      limits: %{memory: 256_000_000, pids: 100},
      restart: :on_failure do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end

    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      limits: %{memory: 512_000_000, pids: 200},
      restart: :on_failure do

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

  attach "web", to: "br0", replicas: 1
end
