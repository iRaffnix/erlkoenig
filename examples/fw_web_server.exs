defmodule FwWebServer do
  @moduledoc """
  Chapter 6 — Web Server Host Firewall.

  Public-facing web server: SSH (rate-limited), HTTP, HTTPS.
  Everything else dropped and counted. Standalone host firewall,
  no containers needed.

  Starten:
    ek dsl compile examples/fw_web_server.exs -o /tmp/fw_web_server.term
    ek config_load /tmp/fw_web_server.term
  """

  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    nft_table :inet, "host" do
      nft_counter "ssh_accepted"
      nft_counter "http_accepted"
      nft_counter "input_drop"

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        # -- Stateful baseline --
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp

        # -- SSH: rate-limited --
        nft_rule :accept, tcp_dport: 22, counter: "ssh_accepted",
                          limit: %{rate: 5, burst: 10}

        # -- Web traffic --
        nft_rule :accept, tcp_dport: 80, counter: "http_accepted"
        nft_rule :accept, tcp_dport: 443

        # -- Runtime services --
        # erlkoenig DNS resolver (even without containers, safe to include)
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 24}, udp_dport: 53

        # -- Default: drop + log --
        nft_rule :drop, log_prefix: "INPUT: ", counter: "input_drop"
      end
    end
  end
end
