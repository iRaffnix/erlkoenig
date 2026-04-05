defmodule Firewall.CtMarkMatch do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      match_mark 1, verdict: :accept
    end
  end
end
