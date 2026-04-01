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
  use Erlkoenig.Stack

  # TODO: migrate observe/policy when supported

  # === DMZ: public-facing reverse proxy ===
  #
  # Single-process: pids: 2 blocks fork() at kernel level.
  # eBPF observe detects any attempt (even if the kernel blocks it)
  # and kills the container — something tried to escape.

  pod "proxy" do
    container "proxy",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      ports: [{8080, 8080}],
      limits: %{memory: "256M", pids: 2},
      restart: :always,
      health_check: [port: 8080, interval: 5000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 8080
        rule :drop, log: "DROP: "
      end
    end
  end

  # === App: internal application tier ===
  #
  # API server: single-process, no forking needed.
  # Worker: the only container that legitimately forks.

  pod "app" do
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      limits: %{memory: "512M", pids: 2},
      restart: {:on_failure, 5},
      health_check: [port: 4000, interval: 10_000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 4000
        rule :drop, log: "DROP: "
      end
    end

    container "worker",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5000"],
      limits: %{memory: "256M", pids: 50},
      restart: :on_failure do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, udp: 53
        rule :accept
      end
    end
  end

  # === Data: isolated storage tier ===
  #
  # Cache: single-process, any fork is an anomaly.

  pod "cache" do
    container "cache",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["6379"],
      limits: %{memory: "128M", pids: 2},
      restart: :always,
      health_check: [port: 6379, interval: 5000, retries: 5] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 6379
        rule :drop, log: "DROP: "
      end
    end
  end

  zone "dmz", subnet: {10, 0, 1, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "proxy", replicas: 1
  end

  zone "app", subnet: {10, 0, 2, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "app", replicas: 1
  end

  zone "data", subnet: {10, 0, 3, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "cache", replicas: 1
  end
end
