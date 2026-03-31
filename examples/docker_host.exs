#!/usr/bin/env elixir
#
# Docker / Container Host
#
# Host running containers with published port ranges.
# Zone-based: external traffic is filtered, Docker bridge is trusted.
#
# Zones:
#   ext     (eth0)    — internet-facing, strict inbound
#   docker  (docker0) — Docker bridge network, trusted
#
# Traffic flow:
#   ext -> host:  SSH + container-exposed ports only
#   docker -> ext: allowed + masqueraded (containers reach internet)
#   ext -> docker: only established (no direct inbound to containers)

defmodule Firewall.DockerHost do
  use ErlkoenigNft.Firewall

  firewall "dockerhost" do
    counters [:ssh, :containers, :banned, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    # --- Zones ---
    zone "ext", interfaces: ["eth0"]
    zone "docker", interfaces: ["docker0"]

    # --- Inbound: protect the host ---

    zone_input "ext", policy: :drop do
      accept :established
      accept :icmp
      accept_protocol :icmpv6
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}

      # Container exposed ports
      accept_tcp_range 3000, 3010                       # web apps
      accept_tcp_range 5432, 5439                       # databases
      accept_tcp_range 6379, 6380                       # Redis

      log_and_drop "DOCKER-DROP: ", counter: :dropped
    end

    zone_input "docker", policy: :accept do
      accept :established
      accept_tcp 22
    end

    # --- Forward: containers to internet ---

    zone_forward "docker", to: "ext", policy: :accept do
      accept :established
      accept :all
    end

    zone_forward "ext", to: "docker", policy: :drop do
      accept :established
    end

    # --- NAT: masquerade container outbound ---

    zone_masquerade "docker", to: "ext"

    # --- Pre-routing: ban list ---

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end
  end
end

defmodule Guard.DockerHost do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 100, window: 10
    detect :port_scan, threshold: 25, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
    whitelist {172, 17, 0, 0}                           # docker network
  end
end

defmodule Watch.DockerHost do
  use ErlkoenigNft.Watch

  watch :docker do
    counter :ssh, :pps, threshold: 10
    counter :dropped, :pps, threshold: 200
    interval 2000
    on_alert :log
  end
end
