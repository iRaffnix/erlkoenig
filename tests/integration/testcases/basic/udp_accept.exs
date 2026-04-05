defmodule Firewall.UdpAccept do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, udp: 53
      nft_rule :accept, udp: 123
    end
  end
end
