defmodule CustomFirewall do
  use Erlkoenig.Firewall

  firewall "webserver" do
    counters [:ssh, :http, :dropped]
    set "blocklist", :ipv4_addr, timeout: 3600

    chain "inbound", hook: :input, policy: :drop do
      accept :established
      accept :icmp
      accept :loopback
      drop_if_in_set "blocklist", counter: :dropped
      accept_tcp 22, counter: :ssh, limit: {5, burst: 2}
      accept_tcp [80, 443]
      accept_udp 53
      connlimit_drop 100
      log_and_drop "BLOCKED: ", counter: :dropped
    end
  end
end
