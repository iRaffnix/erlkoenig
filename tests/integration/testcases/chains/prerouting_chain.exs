defmodule Firewall.PreroutingChain do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "prerouting", hook: :prerouting, type: :filter, priority: :raw, policy: :accept do
      nft_rule :accept, ct: :established
    end
  end
end
