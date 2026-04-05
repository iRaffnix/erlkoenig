defmodule Firewall.LogDrop do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, tcp: 22
      nft_rule :drop, log: "DROP: "
    end
  end
end
