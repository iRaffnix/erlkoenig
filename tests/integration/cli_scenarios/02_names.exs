defmodule CliNames do
  @moduledoc """
  Pathological-name scenario: long, hyphenated, numeric edges.
  Validates that the CLI roundtrips weird-but-valid names through:
    ps, inspect, stop, json output.
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

  # Pod name with many segments to push final container name length:
  # "edge-case-very-long-pod-name-test"-0-"deeply-nested-container-name"
  pod "edge-case-very-long-pod-name-test", strategy: :one_for_one do
    container "deeply-nested-container-name",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 64_000_000, pids: 32}
  end

  # Pod with numeric-only segment in name
  pod "p99", strategy: :one_for_one do
    container "x1",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7778"],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 64_000_000, pids: 32}
  end
end
