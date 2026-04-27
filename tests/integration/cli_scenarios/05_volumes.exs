defmodule CliVolumes do
  @moduledoc """
  Volume scenario: persistent + ephemeral with quotas.
  Validates vol list/inspect/orphans/destroy/set-quota CLI surface
  and the JSON contract for volume records.
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

  pod "store", strategy: :one_for_one do
    container "data",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 64_000_000, pids: 32} do

      # persistent volume — survives down + re-up
      volume "/var/lib/data",
             persist: "primary"

      # ephemeral volume — destroyed at container stop
      volume "/tmp/scratch",
             persist: "scratch",
             ephemeral: true
    end
  end
end
