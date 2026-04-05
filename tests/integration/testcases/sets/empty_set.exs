defmodule Firewall.EmptySet do
  use ErlkoenigNft.Firewall
  firewall "test" do
    set "blocklist", :ipv4_addr
    chain "input", hook: :input, policy: :drop do
      drop_if_in_set "blocklist"
    end
  end
end
