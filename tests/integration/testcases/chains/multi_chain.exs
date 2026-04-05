defmodule Firewall.MultiChain do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22
    end
    chain "forward", hook: :forward, policy: :drop do
      accept :established
    end
    chain "output", hook: :output, policy: :accept do
    end
  end
end
