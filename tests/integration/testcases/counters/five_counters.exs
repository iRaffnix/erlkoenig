defmodule Firewall.FiveCounters do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    nft_counter "ssh"
    nft_counter "http"
    nft_counter "https"
    nft_counter "dns"
    nft_counter "dropped"

    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :accept, tcp: 22, counter: "ssh"
      nft_rule :accept, tcp: 80, counter: "http"
      nft_rule :accept, tcp: 443, counter: "https"
      nft_rule :accept, udp: 53, counter: "dns"
      nft_rule :drop, log: "DROP: ", counter: "dropped"
    end
  end
end
