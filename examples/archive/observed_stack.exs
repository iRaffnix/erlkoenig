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
  use Erlkoenig.Stack

  # TODO: migrate observe/policy when supported

  # === API server: monitored with strict exec policy ===

  pod "api" do
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      ports: [{8080, 8080}],
      limits: %{memory: "256M", pids: 50},
      restart: {:on_failure, 5} do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 8080
        rule :drop, log: "DROP: "
      end
    end
  end

  # === Worker: monitored, more relaxed fork policy ===

  pod "worker" do
    container "worker",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      limits: %{memory: "512M", pids: 100},
      restart: :on_failure do
    end
  end

  # === Database: only OOM monitoring ===

  pod "db" do
    container "db",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      limits: %{memory: "128M", pids: 30},
      restart: :always do
    end
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "api", replicas: 1
    deploy "worker", replicas: 1
    deploy "db", replicas: 1
  end
end
