#!/usr/bin/env elixir
#
# Hardened Web Server
#
# Production web server: SSH + HTTP/HTTPS only.
# Rate-limited SSH, counted services, IPv4+IPv6 blocklists,
# connection flood + port scan detection, NFLOG tracing.

defmodule Firewall.HardenedWebserver do
  use ErlkoenigNft.Firewall

  firewall "webserver" do
    counters [:ssh, :http, :https, :banned, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    # Drop banned IPs before they hit any chain
    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    # Default drop — only allow what we need
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, counter: :ssh, limit: {25, burst: 5}
      accept_tcp 80, counter: :http
      accept_tcp 443, counter: :https
      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "WEB-DROP: ", counter: :dropped
    end
  end
end

defmodule Guard.HardenedWebserver do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 50, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
  end
end

defmodule Watch.HardenedWebserver do
  use ErlkoenigNft.Watch

  watch :webserver do
    counter :ssh, :pps, threshold: 50
    counter :http, :pps, threshold: 1000
    counter :https, :pps, threshold: 1000
    counter :dropped, :pps, threshold: 200
    interval 2000
    on_alert :log
  end
end
