defmodule Firewall.NamedCounter do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_counter "ssh"
    nft_counter "http"

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, tcp: 22, counter: "ssh"
      nft_rule :accept, tcp: 80, counter: "http"
    end
  end
end
