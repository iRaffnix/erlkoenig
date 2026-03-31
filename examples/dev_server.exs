#!/usr/bin/env elixir
#
# Development Server
#
# Multi-service dev box: SSH, HTTP, Phoenix LiveReload, Erlang EPMD +
# distribution, PostgreSQL, Grafana. Relaxed limits, log-and-reject
# (ICMP unreachable instead of silent drop — devs see errors fast).

defmodule Firewall.DevServer do
  use ErlkoenigNft.Firewall

  firewall "devserver" do
    counters [:ssh, :http, :https, :epmd, :phoenix, :postgres, :rejected, :banned]
    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # SSH: still rate-limited even on dev
      accept_tcp 22, counter: :ssh, limit: {25, burst: 5}

      # Web: dev HTTP + HTTPS
      accept_tcp 80, counter: :http
      accept_tcp 443, counter: :https

      # Phoenix dev server + LiveReload websocket
      accept_tcp 4000, counter: :phoenix
      accept_tcp 4001

      # Erlang: EPMD + distribution port range
      accept_tcp 4369, counter: :epmd
      accept_tcp_range 9100, 9155

      # PostgreSQL for local dev
      accept_tcp 5432, counter: :postgres

      # Grafana / monitoring
      accept_tcp 3000

      accept :icmp
      accept_protocol :icmpv6

      # Reject (not drop) — send ICMP unreachable so devs see errors fast
      log_and_reject "DEV-REJECT: "
    end
  end
end

defmodule Guard.DevServer do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 200, window: 10      # relaxed for dev
    detect :port_scan, threshold: 50, window: 60
    ban_duration 600                                     # 10 min only
    whitelist {127, 0, 0, 1}
    whitelist {10, 0, 0, 0}                             # office network
    whitelist {192, 168, 1, 0}                          # home network
    cleanup_interval 60_000
  end
end

defmodule Watch.DevServer do
  use ErlkoenigNft.Watch

  watch :dev do
    counter :ssh, :pps, threshold: 50
    counter :http, :pps, threshold: 500
    counter :postgres, :pps, threshold: 200
    interval 5000                                        # less aggressive polling
    on_alert :log
  end
end
