defmodule CliDensity do
  @moduledoc """
  Density scenario: 12 containers across two pods.
  Validates ps/ct list table alignment, JSON array shape at scale,
  IP pool consumption, and replica-index naming.
  """
  use Erlkoenig.Stack

  host do
    ipvlan "demo", parent: {:dummy, "ek_demo"},
                   subnet: {10, 10, 0, 0, 24}

    nft_host do
      nft_counter "input_drop"
      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop, counter: "input_drop"
      end
    end
  end

  # Pod with 8 replicas — names become web-0-srv, web-1-srv, ..., web-7-srv
  pod "web", strategy: :one_for_one do
    container "srv",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      zone: "demo",
      replicas: 8,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}
  end

  # Separate pod with 4 replicas
  pod "worker", strategy: :one_for_one do
    container "task",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7778"],
      zone: "demo",
      replicas: 4,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}
  end
end
