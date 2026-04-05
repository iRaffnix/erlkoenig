defmodule Firewall.Notrack do
  use ErlkoenigNft.Firewall

  firewall "test" do
    chain "prerouting", hook: :prerouting, priority: -300, policy: :accept do
      notrack 53, :udp
      notrack 123, :udp
    end
  end
end
