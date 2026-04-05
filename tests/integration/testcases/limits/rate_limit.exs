defmodule Firewall.RateLimit do
  use ErlkoenigNft.Firewall

  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22, limit: {10, burst: 3}
    end
  end
end
