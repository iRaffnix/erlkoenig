defmodule Firewall.SetWithCounter do
  use ErlkoenigNft.Firewall
  firewall "test" do
    counters [:banned]
    set "blocklist", :ipv4_addr, elements: ["198.51.100.1"]
    chain "input", hook: :input, policy: :drop do
      drop_if_in_set "blocklist", counter: :banned
    end
  end
end
