defmodule CliPodOneForAll do
  @moduledoc """
  Pod strategy `:one_for_all` (mapped to OTP `:linked`).

  3-container pod where the middle container crashes immediately. After
  the supervisor restarts the group, ALL three containers must show:

    - advanced restart_count
    - new os_pid
    - new container UUID
    - fresh ip allocation (after teardown_veth + IP release)

  Capture must happen between the first group-restart (~0.5s) and the
  second crash (~1.5s with default backoff). The supervisor intensity
  is 5 within 60s — past that, the whole pod tree shuts down.

  Pod name `ofa-` so it does not collide with the rest_for_one case.
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

  pod "ofa", strategy: :one_for_all do
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
