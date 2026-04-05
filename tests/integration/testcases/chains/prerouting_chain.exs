defmodule Firewall.PreroutingChain do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "prerouting", hook: :prerouting, priority: -300, policy: :accept do
      accept :established
    end
  end
end
