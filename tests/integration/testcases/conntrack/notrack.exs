defmodule Firewall.Notrack do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "prerouting", hook: :prerouting, type: :filter, priority: :raw, policy: :accept do
      nft_rule :notrack, udp: 53
      nft_rule :notrack, udp: 123
    end
  end
end
