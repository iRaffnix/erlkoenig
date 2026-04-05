defmodule Firewall.OifnameAccept do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "output", hook: :output, policy: :drop do
      accept :established
      accept_output_interface "eth0"
    end
  end
end
