defmodule Firewall.IpSaddrDrop do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      drop_from "10.0.0.99"
    end
  end
end
