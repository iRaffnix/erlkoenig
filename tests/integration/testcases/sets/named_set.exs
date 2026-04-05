defmodule Firewall.NamedSet do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_set "blocklist", :ipv4_addr, elements: [
      "198.51.100.1",
      "203.0.113.5"
    ]

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :drop, set: "blocklist"
    end
  end
end
