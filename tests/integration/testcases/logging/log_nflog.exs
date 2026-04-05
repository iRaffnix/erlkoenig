defmodule Firewall.LogNflog do
  use ErlkoenigNft.Firewall
  firewall "test" do
    counters [:dropped]
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22
      log_and_drop_nflog "NFLOG-DROP: ", group: 1, counter: :dropped
    end
  end
end
