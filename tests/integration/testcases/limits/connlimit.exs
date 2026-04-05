defmodule Firewall.Connlimit do
  use Erlkoenig.Stack

  nft_table :inet, "test" do
    base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
      nft_rule :accept, ct: :established
      nft_rule :connlimit_drop, max: 10
    end
  end
end
