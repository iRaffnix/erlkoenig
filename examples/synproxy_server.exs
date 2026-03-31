#!/usr/bin/env elixir
#
# SYN Proxy Protected Server
#
# High-traffic web server protected by kernel-level SYN cookies.
# Uses notrack in raw prerouting to bypass conntrack for SYN packets,
# then synproxy intercepts the handshake before creating conntrack state.

defmodule Firewall.SynproxyServer do
  use ErlkoenigNft.Firewall

  firewall "synproxy_server" do
    counters [:http, :https, :ssh, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000, elements: [
      "198.51.100.0",       # known botnet C2
      "203.0.113.10"        # DDoS source
    ]

    # Raw prerouting: notrack on synproxy-protected ports.
    # SYN proxy requires packets to arrive untracked so it can
    # perform the cookie handshake before creating ct entries.
    chain "raw_prerouting", hook: :prerouting, priority: -300, policy: :accept do
      notrack 80, :tcp
      notrack 443, :tcp
    end

    # Synproxy filter + normal rules
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # Drop spoofed source addresses (FIB reverse-path check)
      rpf_check()

      # Kernel validates TCP handshake via SYN cookies
      # before passing the connection to the application
      synproxy [80, 443],
        mss: 1460, wscale: 7, timestamp: true, sack_perm: true

      # After synproxy validates, traffic arrives as established
      accept_tcp 80, counter: :http
      accept_tcp 443, counter: :https

      # Management SSH (not synproxied, just rate-limited)
      accept_tcp 22, counter: :ssh, limit: {5, burst: 3}

      accept :icmp
      log_and_drop_nflog "SYN-DROP: ", group: 1, counter: :dropped
    end
  end
end

defmodule Watch.SynproxyServer do
  use ErlkoenigNft.Watch

  watch :synproxy do
    counter :http, :pps, threshold: 10_000
    counter :https, :pps, threshold: 10_000
    counter :dropped, :pps, threshold: 1000
    interval 1000
    on_alert :log
  end
end
