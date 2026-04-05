defmodule Firewall.SetWithCounter do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_counter "banned"
    nft_set "blocklist", :ipv4_addr, elements: ["198.51.100.1"]

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :drop, set: "blocklist", counter: "banned"
    end
  end
end
