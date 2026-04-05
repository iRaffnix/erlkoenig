defmodule Firewall.OifnameAccept do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "output", hook: :output, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, oif: "eth0"
    end
  end
end
