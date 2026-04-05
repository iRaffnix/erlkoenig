defmodule Firewall.TcpAccept do
  use ErlkoenigNft.Firewall

  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept :loopback
      accept_tcp 22
      accept_tcp 80
      accept_tcp 443
    end
  end
end
