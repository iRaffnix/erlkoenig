#!/usr/bin/env elixir
#
# Database Server (Internal Only)
#
# PostgreSQL accessible only from known app servers.
# No public services except SSH for management.
# Static IP whitelist + connection limits.

defmodule Firewall.DatabaseServer do
  use ErlkoenigNft.Firewall

  firewall "dbserver" do
    counters [:ssh, :postgres, :banned, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :banned
      drop_if_in_set "blocklist6", counter: :banned
    end

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # SSH management, rate-limited
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}

      # PostgreSQL: only from known app servers
      accept_from {10, 0, 1, 10}                        # app-server-1
      accept_from {10, 0, 1, 11}                        # app-server-2
      accept_from {10, 0, 1, 12}                        # app-server-3

      # Connection limit: max 100 concurrent per source IP
      connlimit_drop 100

      accept_tcp 5432, counter: :postgres

      accept :icmp
      log_and_drop "DB-DROP: ", counter: :dropped
    end
  end
end

defmodule Guard.DatabaseServer do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 30, window: 10       # strict
    detect :port_scan, threshold: 5, window: 30         # very strict
    ban_duration 7200
    whitelist {127, 0, 0, 1}
    whitelist {10, 0, 1, 10}                            # app-server-1
    whitelist {10, 0, 1, 11}                            # app-server-2
    whitelist {10, 0, 1, 12}                            # app-server-3
  end
end

defmodule Watch.DatabaseServer do
  use ErlkoenigNft.Watch

  watch :database do
    counter :ssh, :pps, threshold: 5
    counter :postgres, :pps, threshold: 500
    counter :dropped, :pps, threshold: 50
    interval 2000
    on_alert :log
  end
end
