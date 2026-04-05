defmodule Firewall.NamedCounter do
  use ErlkoenigNft.Firewall

  firewall "test" do
    counters [:ssh, :http]

    chain "input", hook: :input, policy: :drop do
      accept_tcp 22, counter: :ssh
      accept_tcp 80, counter: :http
    end
  end
end
