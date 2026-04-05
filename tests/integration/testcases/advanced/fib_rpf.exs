defmodule Firewall.FibRpf do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "prerouting", hook: :prerouting, type: :filter, priority: -200, policy: :accept do
      nft_rule :fib_rpf
    end
  end
end
