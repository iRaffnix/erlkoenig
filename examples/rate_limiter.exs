#!/usr/bin/env elixir
#
# Per-Source Rate Limiter
#
# API server with per-source-IP metering and bandwidth quotas.
# Protects against abusive clients while allowing legitimate traffic.

defmodule Firewall.RateLimiter do
  use ErlkoenigNft.Firewall

  firewall "rate_limiter" do
    counters [:ssh, :api, :uploads, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000, elements: [
      "198.51.100.0",       # known scanner
      "203.0.113.50",       # brute-force origin
      "192.0.2.99"          # abuse report
    ]
    quota :upload_cap, 10_737_418_240, mode: :until    # 10 GB

    # Drop known-bad IPs early
    chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :dropped
    end

    # Default drop — services with rate controls
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # SSH: classic per-rule rate limit
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}

      # API: per-source-IP meter — each client gets 100 req/s
      meter_limit "api_meter", 8080, :tcp,
        rate: 100, burst: 20, unit: :second
      accept_tcp 8080, counter: :api

      # Uploads: allow until 10 GB quota is exhausted
      accept_tcp 9000, counter: :uploads

      accept :icmp
      log_and_drop_nflog "RATE-DROP: ", group: 1, counter: :dropped
    end
  end
end

defmodule Watch.RateLimiter do
  use ErlkoenigNft.Watch

  watch :rate_limiter do
    counter :ssh, :pps, threshold: 20
    counter :api, :pps, threshold: 5000
    counter :dropped, :pps, threshold: 200
    interval 2000
    on_alert :log
  end
end
