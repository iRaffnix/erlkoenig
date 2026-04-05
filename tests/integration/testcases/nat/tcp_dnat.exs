defmodule Firewall.TcpDnat do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "prerouting", hook: :prerouting, type: :nat, priority: -100, policy: :accept do
      nft_rule :dnat, tcp: 8080, addr: "10.0.0.5", dport: 80
    end
  end
end
