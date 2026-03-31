#!/usr/bin/env elixir
#
# Zone-based Home Router
#
# Three zones: WAN (eth0), LAN (eth1 + br0), VPN (wg0).
# Zone-based policies control traffic between interfaces.
# NAT masquerades LAN traffic going out WAN.
#
# The zone macros expand at compile time into standard chains:
#   z_dispatch_input, z_input_wan, z_input_lan, z_input_vpn,
#   z_dispatch_forward, z_fwd_lan_wan, z_fwd_wan_lan, z_fwd_vpn_wan,
#   z_nat_postrouting
#
# No Elixir runtime needed — produces a .term file for erlkoenig_nft.

defmodule Firewall.ZoneRouter do
  use ErlkoenigNft.Firewall

  firewall "router" do
    counters [:ssh, :dns, :dropped, :banned]
    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    # --- Zone definitions ---
    zone "wan", interfaces: ["eth0"]
    zone "lan", interfaces: ["eth1", "br0"]
    zone "vpn", interfaces: ["wg0"]

    # --- Input policies (traffic destined to this host) ---

    zone_input "wan", policy: :drop do
      accept :established
      accept :icmp
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      log_and_drop "WAN-DROP: ", counter: :dropped
    end

    zone_input "lan", policy: :accept do
      accept :established
      accept_tcp 22, counter: :ssh
      accept_udp 53, counter: :dns
    end

    zone_input "vpn", policy: :accept do
      accept :established
      accept_tcp 22
    end

    # --- Forward policies (traffic between zones) ---

    zone_forward "lan", to: "wan", policy: :accept do
      accept :established
      accept :all
    end

    zone_forward "wan", to: "lan", policy: :drop do
      accept :established
    end

    zone_forward "vpn", to: "wan", policy: :accept do
      accept :established
      accept :all
    end

    # --- NAT ---

    zone_masquerade "lan", to: "wan"
    zone_masquerade "vpn", to: "wan"

    # --- Manual chains (coexist with zones) ---

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end
  end
end

defmodule Guard.ZoneRouter do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 200, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 3600
    whitelist {192, 168, 1, 0}
  end
end

defmodule Watch.ZoneRouter do
  use ErlkoenigNft.Watch

  watch :router do
    counter :ssh, :pps, threshold: 20
    counter :dns, :pps, threshold: 5000
    counter :dropped, :pps, threshold: 200
    interval 2000
    on_alert :log
  end
end
