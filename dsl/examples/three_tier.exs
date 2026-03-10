defmodule ThreeTier do
  @moduledoc """
  Three-tier web architecture with network isolation.

  Demonstrates zone-based security boundaries:

    ┌──────────────────────────────┐
    │  Zone: dmz (10.0.1.0/24)    │  ← public, port 8080 exposed
    │  - proxy (reverse proxy)     │
    └──────────┬───────────────────┘
               │
    ┌──────────┴───────────────────┐
    │  Zone: app (10.0.2.0/24)    │  ← internal only, no port mapping
    │  - api (application server)  │
    │  - worker (background jobs)  │
    └──────────┬───────────────────┘
               │
    ┌──────────┴───────────────────┐
    │  Zone: data (10.0.3.0/24)   │  ← isolated, no outbound
    │  - cache (in-memory store)   │
    └──────────────────────────────┘

  Setup:

      source /opt/erlkoenig/activate
      ek-net create dmz  10.0.1.0/24
      ek-net create app  10.0.2.0/24
      ek-net create data 10.0.3.0/24 isolate
      ek-load three_tier.exs
      ek-ps
      ek-top

  Teardown:

      ek-stop proxy && ek-stop api && ek-stop worker && ek-stop cache
      ek-net rm dmz && ek-net rm app && ek-net rm data
  """
  use Erlkoenig.DSL

  # === DMZ: public-facing reverse proxy ===

  container :proxy do
    binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
    zone :dmz
    ip {10, 0, 1, 10}
    args ["8080"]
    ports [{8080, 8080}]
    limits cpu: 2, memory: "256M", pids: 100
    restart :always
    health_check port: 8080, interval: 5000, retries: 3
    firewall :strict, allow_tcp: [8080]
  end

  # === App: internal application tier ===

  container :api do
    binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
    zone :app
    ip {10, 0, 2, 10}
    args ["4000"]
    limits cpu: 4, memory: "512M", pids: 200
    restart {:on_failure, 5}
    health_check port: 4000, interval: 10_000, retries: 3
    firewall :strict, allow_tcp: [4000]
  end

  container :worker do
    binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
    zone :app
    ip {10, 0, 2, 20}
    args ["5000"]
    limits cpu: 2, memory: "256M", pids: 50
    restart :on_failure
    firewall :standard
  end

  # === Data: isolated storage tier ===

  container :cache do
    binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
    zone :data
    ip {10, 0, 3, 10}
    args ["6379"]
    limits cpu: 1, memory: "128M", pids: 30
    restart :always
    health_check port: 6379, interval: 5000, retries: 5
    firewall :strict, allow_tcp: [6379]
  end

end
