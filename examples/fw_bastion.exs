defmodule FwBastion do
  @moduledoc """
  Chapter 6 — Bastion / Jump Host Firewall.

  SSH only from office CIDR (203.0.113.0/24). Reject (not drop) SSH
  from everywhere else for fast client feedback. No forwarding.
  Standalone host firewall, no containers needed.

  Starten:
    ek dsl compile examples/fw_bastion.exs -o /tmp/fw_bastion.term
    ek config_load /tmp/fw_bastion.term
  """

  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    nft_table :inet, "host" do
      nft_counter "ssh_office"
      nft_counter "ssh_rejected"
      nft_counter "forward_drop"

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp

        # -- SSH: only from office --
        nft_rule :accept, tcp_dport: 22,
                          ip_saddr: {203, 0, 113, 0, 24},
                          counter: "ssh_office"

        # Explicit reject for SSH from everywhere else
        nft_rule :reject, tcp_dport: 22, counter: "ssh_rejected"

        nft_rule :drop, log_prefix: "BASTION: "
      end

      # -- No forwarding --
      base_chain "forward", hook: :forward, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :drop, counter: "forward_drop"
      end
    end
  end
end
