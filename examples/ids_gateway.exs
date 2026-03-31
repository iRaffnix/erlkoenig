#!/usr/bin/env elixir
#
# IDS / Traffic Analysis Gateway
#
# Network gateway that queues selected packets to userspace for deep
# inspection (Suricata/Snort) and uses OS fingerprinting to flag
# unusual clients.

defmodule Firewall.IDSGateway do
  use ErlkoenigNft.Firewall

  firewall "ids_gateway" do
    counters [:ssh, :http, :https, :dns, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3_600_000, elements: [
      "198.51.100.0",       # known malware host
      "203.0.113.66"        # C2 server
    ]
    set "watchlist", :ipv4_addr, elements: [
      "10.0.0.50",          # suspicious internal host
      "10.0.0.77"           # under investigation
    ]

    # Drop known-bad IPs
    chain "prerouting", hook: :prerouting, priority: -300, policy: :accept do
      drop_if_in_set "blocklist", counter: :dropped
    end

    # IDS queue + OS fingerprinting + normal services
    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :loopback

      # OS fingerprint: flag non-Linux SYN packets
      # (useful for detecting bots masquerading as browsers)
      match_os "Windows", :drop

      # Queue HTTP/HTTPS to userspace IDS (Suricata/Snort)
      # bypass flag: if queue is full, accept instead of drop
      queue_to 80, :tcp, num: 0, flags: [:bypass]
      queue_to 443, :tcp, num: 1, flags: [:bypass]

      # DNS to userspace for DNS tunneling detection
      queue_to 53, :udp, num: 2, flags: [:bypass]

      # Normal service rules
      accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
      accept_tcp 80, counter: :http
      accept_tcp 443, counter: :https
      accept_udp 53, counter: :dns

      accept :icmp
      log_and_drop_nflog "IDS-DROP: ", group: 1, counter: :dropped
    end

    # Inspect routed traffic
    chain "forward", hook: :forward, type: :filter, policy: :drop do
      accept :established
      log_and_drop "IDS-FWD-DROP: "
    end
  end
end

defmodule Watch.IDSGateway do
  use ErlkoenigNft.Watch

  watch :ids do
    counter :dns, :pps, threshold: 5000
    counter :dropped, :pps, threshold: 500
    interval 2000
    on_alert :log
  end
end
