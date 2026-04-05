defmodule Firewall.ForwardChain do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "forward", hook: :forward, policy: :drop do
      accept :established
    end
  end
end
