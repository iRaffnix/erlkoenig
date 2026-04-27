defmodule CliPodRestForOne do
  @moduledoc """
  Pod strategy `:rest_for_one` (mapped to OTP `:ordered`).

  3-container pod in declared order: front (sleeper), middle (crasher),
  back (sleeper). When middle crashes, OTP restarts middle and all
  children declared *after* it — so middle and back get a new
  lifecycle, but front is untouched.

  Expected post-crash:
    - front  : restart_count == 0, same os_pid as before
    - middle : restart_count > 0, new os_pid
    - back   : restart_count > 0, new os_pid

  Pod name `rfo-` to avoid collision with one_for_all.
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

  pod "rfo", strategy: :rest_for_one do
    container "front",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      args: ["3600"],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}

    container "middle",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-crasher",
      args: [],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}

    container "back",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      args: ["3600"],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}
  end
end
