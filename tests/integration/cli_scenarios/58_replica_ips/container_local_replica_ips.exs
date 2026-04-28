defmodule CliReplicaIpsContainerLocalReject do
  @moduledoc """
  Negative scenario: a container-local nft block referencing
  `{:replica_ips, _, _}`.

  This must be rejected at apply time with the documented
  `unresolvable_replica_ips_in_container_nft` error — silent
  acceptance would weaken the operator's stated firewall intent
  in a way that isn't visible later.

  Driven by 58_replica_ips_contract.escript.
  """
  use Erlkoenig.Stack

  host do
    ipvlan "demo", parent: {:dummy, "ek_demo"},
                   subnet: {10, 10, 0, 0, 24}

    nft_table :inet, "host" do
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

  pod "frontend", strategy: :one_for_one do
    container "app",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16} do
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          # Architecturally invalid: replica_ips refers to a global
          # IP map that the container's isolated netns cannot see.
          # Apply-time MUST fail loud with the documented hint.
          nft_rule :accept,
            ip_saddr: {:replica_ips, "backend", "app"},
            tcp_dport: 7777
        end
      end
    end
  end

  pod "backend", strategy: :one_for_one do
    container "app",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}
  end
end
