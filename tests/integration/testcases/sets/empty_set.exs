defmodule Firewall.EmptySet do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_set "blocklist", :ipv4_addr

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :drop, set: "blocklist"
    end
  end
end
