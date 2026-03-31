#!/usr/bin/env elixir
#
# Zone-based VPN Gateway
#
# Two zones: WAN (eth0) and VPN (wg0).
# WireGuard clients can access the internet through the gateway.
# Strict inbound policy on WAN — only SSH and WireGuard allowed.
# VPN clients get full forwarding to WAN with NAT.
#
# Replaces the manual vpn_gateway.exs with proper zone-based
# interface matching instead of term-level workarounds.

defmodule Firewall.ZoneVPNGateway do
  use ErlkoenigNft.Firewall

  firewall "vpngw" do
    counters [:ssh, :wg, :forwarded, :banned, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    # --- Zones ---
    zone "wan", interfaces: ["eth0"]
    zone "vpn", interfaces: ["wg0"]

    # --- Inbound: protect the gateway ---

    zone_input "wan", policy: :drop do
      accept :established
      accept :icmp
      accept_protocol :icmpv6
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      accept_udp 51820, counter: :wg
      log_and_drop "GW-DROP: ", counter: :dropped
    end

    zone_input "vpn", policy: :accept do
      accept :established
      accept_tcp 22
    end

    # --- Forward: VPN clients to internet ---

    zone_forward "vpn", to: "wan", policy: :accept do
      accept :established
      accept :all
    end

    zone_forward "wan", to: "vpn", policy: :drop do
      accept :established
    end

    # --- NAT: masquerade VPN traffic going out WAN ---

    zone_masquerade "vpn", to: "wan"

    # --- Pre-routing: ban list ---

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end
  end
end

defmodule Guard.ZoneVPNGateway do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 50, window: 10
    detect :port_scan, threshold: 15, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
  end
end

defmodule Watch.ZoneVPNGateway do
  use ErlkoenigNft.Watch

  watch :vpn do
    counter :ssh, :pps, threshold: 10
    counter :dropped, :pps, threshold: 100
    interval 2000
    on_alert :log
  end
end
