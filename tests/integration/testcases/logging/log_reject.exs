defmodule Firewall.LogReject do
  use ErlkoenigNft.Firewall
  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22
      log_and_reject "REJECT: "
    end
  end
end
