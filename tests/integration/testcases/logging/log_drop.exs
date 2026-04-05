defmodule Firewall.LogDrop do
  use ErlkoenigNft.Firewall

  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22
      log_and_drop "DROP: "
    end
  end
end
