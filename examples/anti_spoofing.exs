#!/usr/bin/env elixir
#
# Anti-Spoofing Edge Router
#
# Border router with strict anti-spoofing, multi-field set lookups,
# and verdict map port dispatch for efficient rule evaluation.

defmodule Firewall.AntiSpoofing do
  use ErlkoenigNft.Firewall

  firewall "edge_router" do
    counters [:ssh, :dns, :ntp, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000, elements: [
      "198.51.100.0",       # known spoofing source
      "203.0.113.0",        # bogon prefix
      "192.0.2.1"           # documentation prefix (should never appear)
    ]

    # Concatenated set: only allow specific (source IP, dest port) pairs
    # e.g., only 10.0.0.5 can reach port 5432, only 10.0.0.10 can reach 6379
    concat_set "allow_pairs", [:ipv4_addr, :inet_service]

    # Verdict map: dispatch incoming ports to per-service chains
    vmap "port_vmap", :inet_service, entries: [
      {22, jump: "ssh_chain"},
      {80, jump: "http_chain"},
      {443, jump: "https_chain"},
      {53, :accept}
    ]

    # Raw prerouting: notrack high-volume stateless protocols
    chain "raw_prerouting", hook: :prerouting, priority: -300, policy: :accept do
      # DNS and NTP are stateless — skip conntrack overhead
      notrack 53, :udp
      notrack 123, :udp
    end

    # Anti-spoofing before any processing
    chain "prerouting_filter", hook: :prerouting, priority: -200, policy: :accept do
      drop_if_in_set "blocklist", counter: :dropped
      # BCP38: drop packets with spoofed source addresses
      # (FIB lookup: does a route to the source exist via this iface?)
      rpf_check()
    end

    # Verdict map dispatch + concat set matching
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # Verdict map: single rule dispatches to per-service chains
      # based on destination port lookup.
      # SSH (22) → ssh_chain, HTTP (80) → http_chain,
      # HTTPS (443) → https_chain, DNS (53) → accept directly.
      dispatch :tcp, "port_vmap"

      # Concat set: multi-field match — only allow specific
      # (source IP, destination port) combinations
      drop_if_in_concat_set "allow_pairs", [:ip_saddr, :tcp_dport]

      # Stateless services (notracked above, not in vmap)
      accept_udp 123, counter: :ntp

      accept :icmp
      log_and_drop_nflog "EDGE-DROP: ", group: 1, counter: :dropped
    end

    # Per-service chains (jump targets for port_vmap)
    chain "ssh_chain", hook: :input, priority: 10, policy: :drop do
      accept_tcp 22, counter: :ssh, limit: {5, burst: 3}
    end

    chain "http_chain", hook: :input, priority: 10, policy: :drop do
      accept_tcp 80
    end

    chain "https_chain", hook: :input, priority: 10, policy: :drop do
      accept_tcp 443
    end

    # Strict anti-spoofing for routed traffic
    chain "forward", hook: :forward, type: :filter, policy: :drop do
      accept :established
      rpf_check()
      log_and_drop "EDGE-FWD-DROP: "
    end
  end
end

defmodule Guard.AntiSpoofing do
  use ErlkoenigNft.Guard

  guard do
    detect :conn_flood, threshold: 50, window: 10
    detect :port_scan, threshold: 15, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
  end
end

defmodule Watch.AntiSpoofing do
  use ErlkoenigNft.Watch

  watch :edge do
    counter :dns, :pps, threshold: 5000
    counter :ntp, :pps, threshold: 1000
    counter :dropped, :pps, threshold: 500
    interval 1000
    on_alert :log
  end
end
