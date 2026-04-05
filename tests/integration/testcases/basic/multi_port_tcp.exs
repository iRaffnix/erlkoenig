defmodule Firewall.MultiPortTcp do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, tcp: 22
      nft_rule :accept, tcp: 80
      nft_rule :accept, tcp: 443
      nft_rule :accept, tcp: 8080
      nft_rule :accept, tcp: 8443
    end
  end
end
