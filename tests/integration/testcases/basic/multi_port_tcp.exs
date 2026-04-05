defmodule Firewall.MultiPortTcp do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22
      accept_tcp 80
      accept_tcp 443
      accept_tcp 8080
      accept_tcp 8443
    end
  end
end
