defmodule Firewall.MasqueradeNotVia do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "postrouting", hook: :postrouting, type: :nat, priority: :filter, policy: :accept do
      nft_rule :masquerade, oif_neq: "lo"
    end
  end
end
