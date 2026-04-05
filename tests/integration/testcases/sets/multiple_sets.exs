defmodule Firewall.MultipleSets do
  use ErlkoenigNft.Firewall
  firewall "test" do
    set "blocklist4", :ipv4_addr, elements: ["10.0.0.1"]
    set "blocklist6", :ipv6_addr, elements: ["fe80::1"]
    chain "input", hook: :input, policy: :drop do
      drop_if_in_set "blocklist4"
      drop_if_in_set "blocklist6"
    end
  end
end
