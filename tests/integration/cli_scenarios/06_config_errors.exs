defmodule CliConfigErrors do
  @moduledoc """
  Bad-config scenario: container references a non-existent binary.
  Validate should accept the file (binary path is opaque), but `up`
  must fail loud with a useful operator message.
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

  pod "ghost", strategy: :one_for_one do
    container "missing",
      binary: "/opt/erlkoenig/rt/demo/this-does-not-exist",
      args: [],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}
  end
end
