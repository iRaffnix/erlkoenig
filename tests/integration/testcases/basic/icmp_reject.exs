defmodule Firewall.IcmpReject do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, tcp: 22
      nft_rule :accept, icmp: true
      nft_rule :accept, protocol: :icmpv6
      nft_rule :reject, tcp: 23
    end
  end
end
