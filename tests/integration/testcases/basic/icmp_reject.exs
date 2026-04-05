defmodule Firewall.IcmpReject do
  use ErlkoenigNft.Firewall

  firewall "test" do
    chain "input", hook: :input, policy: :drop do
      accept :established
      accept_tcp 22
      accept :icmp
      accept_protocol :icmpv6
      reject_tcp 23
    end
  end
end
