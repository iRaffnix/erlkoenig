defmodule Firewall.TcpDnat do
  use ErlkoenigNft.Firewall

  firewall "test" do
    chain "prerouting", hook: :prerouting, type: :nat, priority: -100, policy: :accept do
      dnat 8080, "10.0.0.5", 80
    end
  end
end
