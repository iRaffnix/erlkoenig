defmodule Firewall.TcpPortRange do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_tcp_range 8000, 8100
    end
  end
end
