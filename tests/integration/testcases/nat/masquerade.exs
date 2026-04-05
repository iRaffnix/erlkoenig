defmodule Firewall.Masquerade do
  use ErlkoenigNft.Firewall

  firewall "test" do
    chain "postrouting", hook: :postrouting, type: :nat, policy: :accept do
      masquerade()
    end
  end
end
