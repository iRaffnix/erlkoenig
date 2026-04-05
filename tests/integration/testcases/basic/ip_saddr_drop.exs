defmodule Firewall.IpSaddrDrop do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :drop, saddr: "10.0.0.99"
    end
  end
end
