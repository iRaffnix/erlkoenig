defmodule Firewall.MultipleSets do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_set "blocklist4", :ipv4_addr, elements: ["10.0.0.1"]
    nft_set "blocklist6", :ipv6_addr, elements: ["fe80::1"]

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :drop, set: "blocklist4"
      nft_rule :drop, set: "blocklist6", set_type: :ipv6_addr
    end
  end
end
