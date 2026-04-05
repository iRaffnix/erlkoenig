defmodule Firewall.Ipv6Set do
  use ErlkoenigNft.Firewall
  firewall "test" do
    set "blocklist6", :ipv6_addr, elements: ["fe80::1", "fe80::2"]
    chain "input", hook: :input, policy: :drop do
      drop_if_in_set "blocklist6"
    end
  end
end
