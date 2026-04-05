defmodule Firewall.MultiChain do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, tcp: 22
    end

    base_chain "forward", hook: :forward, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
    end

    base_chain "output", hook: :output, type: :filter, priority: :filter, policy: :accept do
    end
  end
end
