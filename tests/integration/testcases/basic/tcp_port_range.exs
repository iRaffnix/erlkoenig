defmodule Firewall.TcpPortRange do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, tcp_range: {8000, 8100}
    end
  end
end
