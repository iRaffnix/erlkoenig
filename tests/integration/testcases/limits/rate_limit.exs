defmodule Firewall.RateLimit do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_counter "tcp_22"

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, tcp: 22, counter: "tcp_22", limit: %{rate: 10, burst: 3}
    end
  end
end
