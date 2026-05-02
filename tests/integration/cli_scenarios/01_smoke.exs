defmodule CliSmoke do
  @moduledoc """
  CLI smoke scenario: minimal stack, exercises the full
  compile → validate → up → ps → inspect → down pipeline against
  the new operator_api wrappers and JSON normalizer.
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

  pod "cli-smoke", strategy: :one_for_one do
    container "web",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 128_000_000, pids: 64}
  end
end
