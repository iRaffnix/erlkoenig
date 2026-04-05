defmodule Firewall.CounterOnUdp do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_counter "dns"

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, udp: 53, counter: "dns"
    end
  end
end
