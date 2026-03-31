#!/usr/bin/env elixir
#
# Default Firewall
#
# Zone-based default config with sensible out-of-the-box security.
# Two zones: "ext" (external, first physical NIC) and "trusted"
# (loopback + optional internal interface).
#
# What it does:
#   - Blocks IPs in the blocklist at prerouting (ban/unban works immediately)
#   - Drops unsolicited inbound on the external interface
#   - Allows SSH (rate-limited), ICMP, and established connections
#   - Forward and NAT ready for when you add more zones
#
# Customize by adding zones, opening ports, or replacing this
# with a purpose-built config: erlkoenig apply <your_config.exs>

defmodule Firewall.Default do
  use ErlkoenigNft.Firewall

  firewall "erlkoenig" do
    counters [:ssh, :icmp, :dropped, :banned]

    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    # --- Zones ---
    zone "ext", interfaces: ["eth0"]

    # --- Inbound: protect this host ---

    zone_input "ext", policy: :drop do
      accept :established
      accept :icmp
      accept_protocol :icmpv6
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      log_and_drop "DROP: ", counter: :dropped
    end

    # --- Pre-routing: blocklist ---

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end
  end
end

defmodule Guard.Default do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 50, window: 10
    detect :port_scan, threshold: 15, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
  end
end

defmodule Watch.Default do
  use ErlkoenigNft.Watch

  watch :default do
    counter :ssh, :pps, threshold: 20
    counter :dropped, :pps, threshold: 100
    interval 2000
    on_alert :log
  end
end
