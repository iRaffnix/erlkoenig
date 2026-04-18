defmodule FwNatGateway do
  @moduledoc """
  Chapter 6 — NAT Gateway with Masquerade.

  Gateway that NATs a private subnet (10.0.0.0/16) to the internet
  via eth0. Anti-spoofing via FIB reverse-path filtering. Standalone
  host firewall, no containers needed.

  Starten:
    ek dsl compile examples/fw_nat_gateway.exs -o /tmp/fw_nat_gateway.term
    ek config_load /tmp/fw_nat_gateway.term
  """

  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    nft_table :inet, "host" do
      nft_counter "forward_drop"

      # -- Input: standard hardened host --
      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22,
                          ip_saddr: {10, 0, 0, 0, 16}

        # -- Runtime services --
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 16}, udp_dport: 53

        nft_rule :drop, log_prefix: "GW-IN: "
      end

      # -- Forward: allow internal -> internet --
      base_chain "forward", hook: :forward, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 16},
                          oifname: "eth0"

        nft_rule :drop, log_prefix: "GW-FWD: ",
                        counter: "forward_drop"
      end

      # -- Postrouting: masquerade outbound traffic --
      base_chain "postrouting", hook: :postrouting, type: :nat,
                 priority: :srcnat, policy: :accept do

        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 16},
                              oifname: "eth0"
      end

      # -- Prerouting: anti-spoofing --
      base_chain "prerouting", hook: :prerouting, type: :filter,
                 priority: :raw, policy: :accept do

        nft_rule :fib_rpf
      end
    end
  end
end
