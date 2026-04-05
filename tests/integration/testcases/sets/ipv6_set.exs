defmodule Firewall.Ipv6Set do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_set "blocklist6", :ipv6_addr, elements: ["fe80::1", "fe80::2"]

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :drop, set: "blocklist6", set_type: :ipv6_addr
    end
  end
end
