defmodule HardenedWorker do
  use Erlkoenig.Stack

  # ── Gehärteter Worker mit Limits + Egress-Filter ──────
  #
  # Zeigt: Memory/PID-Limits, Health-Checks, Restart-Policy,
  # nft-transparente Firewall mit Egress-Filter.
  #
  # Der Worker darf nur antworten (ct established).
  # Jeder aktive Outbound-Versuch wird gedroppt + gezählt.

  host do
    bridge "compute", subnet: {10, 0, 0, 0, 24}

    nft_table :inet, "erlkoenig" do
      nft_counter "forward_drop"
      nft_counter "worker_drop"

      base_chain "forward",
        hook: :forward, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :jump, iifname: {:veth_of, "worker", "worker"}, to: "from-worker"
        nft_rule :drop, log_prefix: "FWD: ", counter: "forward_drop"
      end

      # Worker: nur antworten, kein aktiver Outbound
      nft_chain "from-worker" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :drop, counter: "worker_drop"
      end
    end
  end

  pod "worker", strategy: :one_for_one do
    container "worker",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9090"],
      limits: %{memory: 536_870_912, pids: 100},
      seccomp: :default,
      restart: {:on_failure, 10},
      health_check: [port: 9090, interval: 15_000, retries: 5] do

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

  attach "worker", to: "compute", replicas: 1
end
