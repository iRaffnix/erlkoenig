#!/usr/bin/env elixir
#
# DNS Server
#
# Authoritative or recursive DNS: UDP 53 + TCP 53.
# Rate-limited to prevent DNS amplification abuse.
# Separate counters and limits for UDP vs TCP.

defmodule Firewall.DNSServer do
  use ErlkoenigNft.Firewall

  firewall "dnsserver" do
    counters [:ssh, :dns_udp, :dns_tcp, :banned, :dropped]
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

      # DNS UDP: rate-limited to prevent amplification
      accept_udp 53, counter: :dns_udp

      # DNS TCP: for zone transfers and large responses
      accept_tcp 53, counter: :dns_tcp

      accept :icmp
      accept_protocol :icmpv6
      log_and_drop "DNS-DROP: ", counter: :dropped
    end
  end
end

defmodule Guard.DNSServer do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 200, window: 10      # DNS = many connections
    detect :port_scan, threshold: 10, window: 30
    ban_duration 1800
    whitelist {127, 0, 0, 1}
    cleanup_interval 15_000
  end
end

defmodule Watch.DNSServer do
  use ErlkoenigNft.Watch

  watch :dns do
    counter :dns_udp, :pps, threshold: 2000             # amplification alert
    counter :dns_tcp, :pps, threshold: 500
    counter :dropped, :pps, threshold: 500
    interval 1000                                        # fast polling for DNS
    on_alert :log
  end
end
