defmodule Firewall.Snat do
  use ErlkoenigNft.Firewall

  firewall "test" do
    chain "postrouting", hook: :postrouting, type: :nat, priority: 100, policy: :accept do
      snat "192.168.1.1", 0
    end
  end
end
