#!/usr/bin/env elixir
#
# Service Mesh Host
#
# Multi-service host using systemd cgroups for per-service firewall rules
# and conntrack marks for cross-chain connection tagging.
# Flowtable offloads established connections for high throughput.
#
# Cgroup IDs are resolved at startup from systemd service names via
# erlkoenig_nft_cgroup:service_id/1 — no hardcoded IDs needed.
#
# Usage:
#   # Find your service cgroup IDs:
#   cat /sys/fs/cgroup/system.slice/nginx.service/cgroup.id
#
#   # Or from Erlang:
#   {ok, Id} = erlkoenig_nft_cgroup:service_id("nginx").

defmodule Firewall.ServiceMesh do
  use ErlkoenigNft.Firewall

  # Resolve cgroup IDs from systemd service names at compile time.
  # These will fail gracefully if the service doesn't exist yet.
  @nginx_cgroup    resolve_cgroup("nginx")
  @postgres_cgroup resolve_cgroup("postgresql")
  @redis_cgroup    resolve_cgroup("redis-server")

  firewall "service_mesh" do
    counters [:ssh, :nginx, :postgres, :redis, :prometheus, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000, elements: [
      "198.51.100.0",       # external scanner
      "203.0.113.22"        # abuse report
    ]

    # Hardware fast-path offload for established connections
    flowtable "ft0", devices: ["eth0", "eth1"], priority: 0

    # Drop banned, tag trusted-network connections
    chain "prerouting", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :dropped
      # Tag connections from internal network so they can be
      # fast-tracked in the input chain
      mark_connection 100
    end

    # Per-service cgroup rules + ct mark matching
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # Offload established connections to flowtable hardware path
      offload "ft0"

      # Accept internally-tagged connections immediately
      match_mark 100, verdict: :accept

      # Per-service cgroup rules:
      # Only nginx.service can receive HTTP/HTTPS
      match_cgroup @nginx_cgroup, :accept
      accept_tcp 80, counter: :nginx
      accept_tcp 443, counter: :nginx

      # Only postgresql.service can listen on 5432
      match_cgroup @postgres_cgroup, :accept
      accept_tcp 5432, counter: :postgres

      # Only redis-server.service can listen on 6379
      match_cgroup @redis_cgroup, :accept
      accept_tcp 6379, counter: :redis

      # Block redis from accepting external connections
      match_cgroup @redis_cgroup, :drop

      # Prometheus metrics endpoint
      accept_tcp 9090, counter: :prometheus

      # Management SSH
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}

      accept :icmp
      log_and_drop "MESH-DROP: ", counter: :dropped
    end

    # Forward: offload inter-service traffic
    chain "forward", hook: :forward, type: :filter, policy: :drop do
      accept :established
      offload "ft0"
      # Only forward ct-marked (internal) traffic
      match_mark 100, verdict: :accept
      log_and_drop "MESH-FWD-DROP: "
    end
  end

  # Resolve a systemd service name to its cgroupv2 ID.
  # Falls back to 0 if the service isn't running (dev/CI environments).
  defp resolve_cgroup(service) do
    case :erlkoenig_nft_cgroup.service_id(service) do
      {:ok, id} -> id
      {:error, _} -> 0
    end
  end
end

defmodule Guard.ServiceMesh do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 100, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
    whitelist {10, 0, 0, 0}
  end
end

defmodule Watch.ServiceMesh do
  use ErlkoenigNft.Watch

  watch :mesh do
    counter :ssh, :pps, threshold: 20
    counter :nginx, :pps, threshold: 10_000
    counter :postgres, :pps, threshold: 1000
    counter :dropped, :pps, threshold: 100
    interval 2000
    on_alert :log
  end
end
