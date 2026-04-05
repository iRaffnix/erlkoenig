defmodule Firewall.CtMarkMatch do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :ct_mark_match, value: 1, verdict: :accept
    end
  end
end
