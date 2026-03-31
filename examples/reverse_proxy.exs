#!/usr/bin/env elixir
#
# Reverse Proxy / Load Balancer
#
# Public HTTP/HTTPS forwarded to internal backend pool via DNAT.
# Connection limits to prevent abuse. Proxy itself only SSH.

defmodule Firewall.ReverseProxy do
  use ErlkoenigNft.Firewall

  firewall "proxy" do
    counters [:ssh, :http_fwd, :https_fwd, :banned, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    # Drop banned
    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    # DNAT to backend (nat chain type requires term-level config for dnat rules)
    # chain "prerouting_nat", hook: :prerouting, type: :nat, priority: -100, policy: :accept
    #   dnat {10, 0, 1, 100}, 80     -> backend:80
    #   dnat {10, 0, 1, 100}, 443    -> backend:443

    # Protect the proxy itself
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      connlimit_drop 200                                # max 200 conns per source
      accept_tcp 80, counter: :http_fwd
      accept_tcp 443, counter: :https_fwd
      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "PROXY-DROP: ", counter: :dropped
    end

    # Forward traffic to/from backends
    chain "forward", hook: :forward, type: :filter, policy: :drop do
      accept :established
      accept_from {10, 0, 1, 100}                       # backend server
      log_and_drop "PROXY-FWD-DROP: "
    end

    # Masquerade return traffic
    chain "masq", hook: :postrouting, type: :nat, policy: :accept do
      # masq rule requires term-level config
    end
  end
end

defmodule Guard.ReverseProxy do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 200, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
    whitelist {10, 0, 1, 100}                           # backend
  end
end

defmodule Watch.ReverseProxy do
  use ErlkoenigNft.Watch

  watch :proxy do
    counter :http_fwd, :pps, threshold: 2000
    counter :https_fwd, :pps, threshold: 2000
    counter :dropped, :pps, threshold: 500
    interval 2000
    on_alert :log
    on_alert {:webhook, "https://alerts.internal/proxy"}
  end
end
