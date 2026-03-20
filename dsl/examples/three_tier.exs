defmodule ThreeTier do
  @moduledoc """
  Three-tier web architecture with network isolation.

  Demonstrates zone-based security boundaries with eBPF
  runtime observability and policy enforcement:

    ┌──────────────────────────────┐
    │  Zone: dmz (10.0.1.0/24)    │  ← public, port 8080 exposed
    │  - proxy (reverse proxy)     │    pids: 2, no fork allowed
    └──────────┬───────────────────┘
               │
    ┌──────────┴───────────────────┐
    │  Zone: app (10.0.2.0/24)    │  ← internal only, no port mapping
    │  - api (application server)  │    pids: 2, no fork allowed
    │  - worker (background jobs)  │    pids: 50, may fork (sub-tasks)
    └──────────┬───────────────────┘
               │
    ┌──────────┴───────────────────┐
    │  Zone: data (10.0.3.0/24)   │  ← isolated, no outbound
    │  - cache (in-memory store)   │    pids: 2, no fork allowed
    └──────────────────────────────┘

  Fork policy: pids: 2 = hard kernel limit (init + app, nothing else).
  eBPF observe detects any fork attempt — even failed ones trigger
  the policy engine. Only the worker gets a higher pid limit because
  it spawns sub-tasks by design.

  Setup:

      ek-net create dmz  10.0.1.0/24
      ek-net create app  10.0.2.0/24
      ek-net create data 10.0.3.0/24 isolate
      ek-load three_tier.exs
      ek-ps
      ek-top
      ek-eval 'erlkoenig_metrics:all_stats().'

  Teardown:

      ek-stop proxy && ek-stop api && ek-stop worker && ek-stop cache
      ek-net rm dmz && ek-net rm app && ek-net rm data
  """
  use Erlkoenig.DSL

  # === DMZ: public-facing reverse proxy ===
  #
  # Single-process: pids: 2 blocks fork() at kernel level.
  # eBPF observe detects any attempt (even if the kernel blocks it)
  # and kills the container — something tried to escape.

  container :proxy do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"
    zone :dmz
    ip {10, 0, 1, 10}
    args ["8080"]
    ports [{8080, 8080}]
    limits cpu: 2, memory: "256M", pids: 2
    restart :always
    health_check port: 8080, interval: 5000, retries: 3

    observe :all

    policy do
      max_forks 1, per: :minute
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

  # === App: internal application tier ===
  #
  # API server: single-process, no forking needed.

  container :api do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"
    zone :app
    ip {10, 0, 2, 10}
    args ["4000"]
    limits cpu: 4, memory: "512M", pids: 2
    restart {:on_failure, 5}
    health_check port: 4000, interval: 10_000, retries: 3

    observe :all

    policy do
      max_forks 1, per: :minute
      on_fork_flood :kill
      on_oom :restart
    end

    firewall do
      accept :established
      accept :icmp
      accept_tcp 4000
      log_and_drop "DROP: "
    end
  end

  # Worker: the only container that legitimately forks.
  # Gets a higher pid limit and a generous fork budget.
  # Fork flood still kills — 200/min is way beyond normal.

  container :worker do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"
    zone :app
    ip {10, 0, 2, 20}
    args ["5000"]
    limits cpu: 2, memory: "256M", pids: 50
    restart :on_failure

    observe :forks, :exits, :oom

    policy do
      max_forks 200, per: :minute
      on_fork_flood :kill
      on_oom :restart
    end

    firewall do
      accept :established
      accept :icmp
      accept_udp 53
      accept :all
    end
  end

  # === Data: isolated storage tier ===
  #
  # Cache: single-process, any fork is an anomaly.

  container :cache do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"
    zone :data
    ip {10, 0, 3, 10}
    args ["6379"]
    limits cpu: 1, memory: "128M", pids: 2
    restart :always
    health_check port: 6379, interval: 5000, retries: 5

    observe :forks, :oom

    policy do
      max_forks 1, per: :minute
      on_fork_flood :kill
      on_oom :alert
    end

    firewall do
      accept :established
      accept :icmp
      accept_tcp 6379
      log_and_drop "DROP: "
    end
  end

end
