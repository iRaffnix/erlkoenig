defmodule ThreeTierLive do
  use Erlkoenig.DSL

  @moduledoc """
  Production-grade 3-tier stack: Reverse Proxy → API Server → SQLite DB.

  All three are statically linked Go binaries, no config files needed.
  rqlite provides distributed SQLite with Raft consensus via HTTP API.

      ek-load /opt/erlkoenig/examples/three_tier_live.exs
      curl http://localhost/api/users
  """

  container :db do
    binary "/opt/erlkoenig/rt/rqlited"
    ip {10, 0, 0, 30}
    args ["-node-id", "1",
          "-http-addr", "10.0.0.30:4001",
          "-raft-addr", "10.0.0.30:4002",
          "/tmp/rqlite-data"]
    limits cpu: 2, memory: "128M", pids: 50
    restart :on_failure
    health_check port: 4001, interval: 5000, retries: 5
  end

  container :api do
    binary "/opt/erlkoenig/rt/api-server"
    ip {10, 0, 0, 20}
    args ["8080", "http://10.0.0.30:4001"]
    limits cpu: 1, memory: "64M", pids: 50
    restart :on_failure
    health_check port: 8080, interval: 5000, retries: 3
  end

  container :proxy do
    binary "/opt/erlkoenig/rt/reverse-proxy"
    ip {10, 0, 0, 10}
    args [":8080", "http://10.0.0.20:8080"]
    ports [{80, 8080}]
    limits cpu: 1, memory: "64M", pids: 50
    restart :on_failure
    health_check port: 8080, interval: 5000, retries: 3
  end
end
