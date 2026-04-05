defmodule Firewall.NamedSet do
  use ErlkoenigNft.Firewall

  firewall "test" do
    set "blocklist", :ipv4_addr, elements: [
      "198.51.100.1",
      "203.0.113.5"
    ]

    chain "input", hook: :input, policy: :drop do
      drop_if_in_set "blocklist"
    end
  end
end
