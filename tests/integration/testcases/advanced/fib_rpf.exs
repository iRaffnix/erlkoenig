defmodule Firewall.FibRpf do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "prerouting", hook: :prerouting, priority: -200, policy: :accept do
      rpf_check()
    end
  end
end
