defmodule Firewall.FiveCounters do
  use ErlkoenigNft.Firewall
  firewall "test" do
    counters [:ssh, :http, :https, :dns, :dropped]
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22, counter: :ssh
      accept_tcp 80, counter: :http
      accept_tcp 443, counter: :https
      accept_udp 53, counter: :dns
      log_and_drop "DROP: ", counter: :dropped
    end
  end
end
