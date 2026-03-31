#!/usr/bin/env elixir
#
# NAT Router with Flow Offload
#
# Home/office router doing NAT between LAN (eth1) and WAN (eth0).
# Zone-based forwarding with flowtable offloading for established flows.
#
# Without offload: every packet walks all rules (~2 Gbit/s on commodity hardware)
# With offload:    packets skip nftables entirely (~10 Gbit/s, or line rate with NIC offload)
#
# Zones:
#   wan (eth0) — internet uplink
#   lan (eth1) — local network
#
# The flow offload flowtable binds to both interfaces so established
# flows between LAN and WAN get offloaded at ingress.

defmodule Firewall.NATRouter do
  use ErlkoenigNft.Firewall

  firewall "router" do
    counters [:ssh, :dns, :dhcp, :forwarded, :banned, :dropped]

    set "blocklist", :ipv4_addr, timeout: 3_600_000, elements: [
      "198.51.100.0",       # known scanner
      "203.0.113.50"        # abuse report
    ]

    set "trusted_lan", :ipv4_addr, elements: [
      "192.168.1.10",       # admin workstation
      "192.168.1.11"        # monitoring server
    ]

    # Flowtable: bind to both interfaces so established flows
    # between LAN and WAN get offloaded at ingress
    flowtable "ft0", devices: ["eth0", "eth1"], priority: 0

    # --- Zones ---
    zone "wan", interfaces: ["eth0"]
    zone "lan", interfaces: ["eth1"]

    # --- Inbound: protect the router ---

    zone_input "wan", policy: :drop do
      accept :established
      accept :icmp
      accept_protocol :icmpv6
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      log_and_drop "RTR-DROP: ", counter: :dropped
    end

    zone_input "lan", policy: :accept do
      accept :established
      accept_tcp 22, counter: :ssh
      accept_udp 53, counter: :dns
      accept_udp 67, counter: :dhcp
    end

    # --- Forward: LAN to WAN with flow offload ---
    # First packet evaluates rules normally, then offload kicks in
    # and subsequent packets skip nftables entirely.

    zone_forward "lan", to: "wan", policy: :accept do
      offload "ft0"
      accept :established
      accept :all
    end

    zone_forward "wan", to: "lan", policy: :drop do
      accept :established
    end

    # --- NAT ---

    zone_masquerade "lan", to: "wan"

    # --- Pre-routing: ban list ---

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
    end
  end
end

defmodule Guard.NATRouter do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 200, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 3600
    whitelist {192, 168, 1, 0}
  end
end

defmodule Watch.NATRouter do
  use ErlkoenigNft.Watch

  watch :router do
    counter :ssh, :pps, threshold: 20
    counter :dns, :pps, threshold: 5000
    counter :forwarded, :pps, threshold: 50_000
    counter :dropped, :pps, threshold: 200
    interval 2000
    on_alert :log
  end
end
