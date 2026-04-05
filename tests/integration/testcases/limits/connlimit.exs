defmodule Firewall.Connlimit do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      connlimit_drop 10
    end
  end
end
