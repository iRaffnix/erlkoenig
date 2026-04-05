defmodule Firewall.MasqueradeNotVia do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "postrouting", hook: :postrouting, type: :nat, policy: :accept do
      masquerade_not_via "lo"
    end
  end
end
