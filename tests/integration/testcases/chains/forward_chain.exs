defmodule Firewall.ForwardChain do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "forward", hook: :forward, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
    end
  end
end
