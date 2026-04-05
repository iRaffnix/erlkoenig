defmodule Firewall.LogNflog do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_counter "dropped"

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, tcp: 22
      nft_rule :drop, log: %{prefix: "NFLOG-DROP: ", group: 1}, counter: "dropped"
    end
  end
end
