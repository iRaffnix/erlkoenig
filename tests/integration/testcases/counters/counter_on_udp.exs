defmodule Firewall.CounterOnUdp do
  use ErlkoenigNft.Firewall
  firewall "test" do
    counters [:dns]
    chain "input", hook: :input, policy: :drop do
      accept_udp 53, counter: :dns
    end
  end
end
