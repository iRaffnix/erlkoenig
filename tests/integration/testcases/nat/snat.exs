defmodule Firewall.Snat do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "postrouting", hook: :postrouting, type: :nat, priority: 100, policy: :accept do
      nft_rule :snat, addr: "192.168.1.1", port: 0
    end
  end
end
