defmodule ObservedStack do
  @moduledoc """
  Container stack with eBPF observability and runtime policies.

  Demonstrates the `observe` and `policy` DSL sections:
  - Real-time fork/exec/exit/oom tracking via kernel tracepoints
  - Fork-bomb detection with automatic kill
  - OOM auto-restart
  - Exec-guard: only allowed binaries may run

  Setup:

      ek-load observed_stack.exs
      ek-ps
      ek-eval 'erlkoenig_metrics:all_stats().'

  """
  use Erlkoenig.DSL

  # === API server: monitored with strict exec policy ===

  container :api do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"
    ip {10, 0, 0, 10}
    args ["8080"]
    ports [{8080, 8080}]
    limits cpu: 2, memory: "256M", pids: 50
    restart {:on_failure, 5}

    observe :all

    policy do
      max_forks 20, per: :minute
      max_forks 5, per: :second
      on_fork_flood :kill
      on_oom :restart
      allowed_comms ["app"]
      on_unexpected_exec :kill
    end

    firewall do
      accept :established
      accept :icmp
      accept_tcp 8080
      log_and_drop "DROP: "
    end
  end

  # === Worker: monitored, more relaxed fork policy ===

  container :worker do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper"
    ip {10, 0, 0, 20}
    limits cpu: 4, memory: "512M", pids: 100
    restart :on_failure

    observe :forks, :exits, :oom

    policy do
      max_forks 100, per: :minute
      on_fork_flood :alert
      on_oom :restart
    end
  end

  # === Database: only OOM monitoring ===

  container :db do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper"
    ip {10, 0, 0, 30}
    limits cpu: 2, memory: "128M", pids: 30
    restart :always

    observe :oom

    policy do
      on_oom :alert
    end
  end
end
