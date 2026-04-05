defmodule Firewall.UdpAccept do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_udp 53
      accept_udp 123
    end
  end
end
