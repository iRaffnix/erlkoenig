defmodule CliLifecycle do
  @moduledoc """
  Lifecycle/restart-policy scenario.

  Validates that the four restart policies behave per spec:

    - :permanent   → always restart, ignore exit code (sleeper stays up)
    - :transient   → restart only on abnormal exit (clean-exit stays stopped)
    - :transient + crasher → keeps restarting until quarantine kicks in
    - :temporary   → never restart (crasher exits once, stays failed)

  Also validates that:
    - `restart_count` advances on each restart cycle
    - `user_stopped` flag prevents restart after manual stop
    - timeline emits creating → namespace_ready → running → stopped → restarting cycles
    - `ek ct list` reports the right state per container
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

  # Always-on container: should run, restart_count stays 0.
  pod "perm", strategy: :one_for_one do
    container "sleeper",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      args: ["3600"],
      zone: "demo",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 32_000_000, pids: 16}
  end

  # Clean-exit container with :transient — should NOT restart.
  pod "transclean", strategy: :one_for_one do
    container "hello",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-hello_output",
      args: [],
      zone: "demo",
      replicas: 1,
      restart: :transient,
      limits: %{memory: 32_000_000, pids: 16}
  end

  # Crashing container with :transient — should keep restarting until quarantine.
  pod "transcrash", strategy: :one_for_one do
    container "boom",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-crasher",
      args: [],
      zone: "demo",
      replicas: 1,
      restart: :transient,
      limits: %{memory: 32_000_000, pids: 16}
  end

  # Crashing container with :temporary — should NEVER restart.
  pod "tempcrash", strategy: :one_for_one do
    container "once",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-crasher",
      args: [],
      zone: "demo",
      replicas: 1,
      restart: :temporary,
      limits: %{memory: 32_000_000, pids: 16}
  end
end
