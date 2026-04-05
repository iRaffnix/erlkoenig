defmodule Firewall.CtMarkSet do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "input", hook: :input, policy: :accept do
      mark_connection 1
    end
  end
end
