defmodule CliReplicaIpsTwoTier do
  @moduledoc """
  Two-tier topology pinning the cross-product expansion of
  `{:replica_ips, Pod, Container}` host-firewall rules.

  - frontend pod: 2 replicas of `app`
  - backend pod:  3 replicas of `app`
  - one host nft accept rule: frontend × backend on tcp/4000

  Expectations the integration test (58) asserts:
    * 2 × 3 == 6 expanded nft rules in the host forward chain
    * each expanded rule has concrete saddr + daddr (no
      `__unresolved__` placeholder)
    * the set of (saddr, daddr) pairs equals the full cross-product
    * `tcp dport 4000` appears exactly 6 times in the table dump
  """
  use Erlkoenig.Stack

  host do
    ipvlan "demo", parent: {:dummy, "ek_demo"},
                   subnet: {10, 10, 0, 0, 24}

    nft_table :inet, "host" do
      nft_counter "input_drop"
      nft_counter "ricochet_drop"

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop, counter: "input_drop"
      end

      base_chain "forward", hook: :forward, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept,
          ip_saddr: {:replica_ips, "frontend", "app"},
          ip_daddr: {:replica_ips, "backend",  "app"},
          tcp_dport: 4000
        nft_rule :drop, counter: "ricochet_drop"
      end
    end
  end

  pod "frontend", strategy: :one_for_one do
    container "app",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      zone: "demo",
      replicas: 2,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}
  end

  pod "backend", strategy: :one_for_one do
    container "app",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      zone: "demo",
      replicas: 3,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}
  end
end
