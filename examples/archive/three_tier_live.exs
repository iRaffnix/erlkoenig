defmodule ThreeTierLive do
  use Erlkoenig.Stack

  @moduledoc """
  Production-grade 3-tier stack: Reverse Proxy → API Server → SQLite DB.

  All three are statically linked Go binaries, no config files needed.
  rqlite provides distributed SQLite with Raft consensus via HTTP API.

      ek-load /opt/erlkoenig/examples/three_tier_live.exs
      curl http://localhost/api/users
  """

  pod "three_tier" do
    container "db",
      binary: "/opt/erlkoenig/rt/rqlited",
      args: ["-node-id", "1",
             "-http-addr", "10.0.0.30:4001",
             "-raft-addr", "10.0.0.30:4002",
             "/tmp/rqlite-data"],
      limits: %{memory: "128M", pids: 50},
      restart: :on_failure,
      health_check: [port: 4001, interval: 5000, retries: 5] do
    end

    container "api",
      binary: "/opt/erlkoenig/rt/api-server",
      args: ["8080", "http://10.0.0.30:4001"],
      limits: %{memory: "64M", pids: 50},
      restart: :on_failure,
      health_check: [port: 8080, interval: 5000, retries: 3] do
    end

    container "proxy",
      binary: "/opt/erlkoenig/rt/reverse-proxy",
      args: [":8080", "http://10.0.0.20:8080"],
      ports: [{80, 8080}],
      limits: %{memory: "64M", pids: 50},
      restart: :on_failure,
      health_check: [port: 8080, interval: 5000, retries: 3] do
    end
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "three_tier", replicas: 1
  end
end
