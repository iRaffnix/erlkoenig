defmodule CliCrashloop do
  @moduledoc """
  Crashloop scenario: a binary that exits immediately. With
  `restart: :permanent` and the default quarantine threshold (5
  crashes / 60s window), the hash should land in the quarantine list
  shortly after `up`.

  Validates the operator-facing quarantine API: list, manual add,
  manual remove.
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

  pod "crash", strategy: :one_for_one do
    container "boom",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-crasher",
      args: [],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}
  end
end
