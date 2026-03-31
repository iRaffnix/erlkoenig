#!/usr/bin/env elixir
#
# Game / Media Server
#
# Game server with UDP port ranges and high connection limits.
# Voice chat (UDP), game traffic (UDP range), web admin panel (TCP range).
# High thresholds — games generate many legitimate connections.

defmodule Firewall.GameServer do
  use ErlkoenigNft.Firewall

  firewall "gameserver" do
    counters [:ssh, :game, :voice, :webpanel, :banned, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}

      # Game traffic: UDP port range 27015-27030
      accept_udp_range 27015, 27030

      # Voice chat: fixed UDP port
      accept_udp 9987, counter: :voice

      # Web admin panel: TCP port range 8080-8089
      accept_tcp_range 8080, 8089

      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "GAME-DROP: ", counter: :dropped
    end
  end
end

defmodule Guard.GameServer do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 500, window: 10      # games = high traffic
    detect :port_scan, threshold: 30, window: 60
    ban_duration 1800
    whitelist {127, 0, 0, 1}
  end
end

defmodule Watch.GameServer do
  use ErlkoenigNft.Watch

  watch :game do
    counter :game, :pps, threshold: 5000
    counter :voice, :pps, threshold: 1000
    counter :dropped, :pps, threshold: 500
    interval 2000
    on_alert :log
  end
end
