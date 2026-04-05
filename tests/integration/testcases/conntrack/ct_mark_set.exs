defmodule Firewall.CtMarkSet do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :accept do
      nft_rule :ct_mark_set, value: 1
    end
  end
end
