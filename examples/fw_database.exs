defmodule FwDatabase do
  @moduledoc """
  Chapter 6 — Database Server Host Firewall.

  PostgreSQL accepts only from app-server IPs (via set). No outbound
  connections allowed except DNS and established replies. Standalone
  host firewall, no containers needed.

  Starten:
    ek dsl compile examples/fw_database.exs -o /tmp/fw_database.term
    ek config_load /tmp/fw_database.term
  """

  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    nft_table :inet, "host" do
      nft_set "app_servers", :ipv4_addr
      nft_counter "pg_accepted"
      nft_counter "input_drop"
      nft_counter "output_drop"

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22,
                          ip_saddr: {10, 0, 1, 0, 24}

        # -- PostgreSQL: only from app servers --
        nft_rule :accept, tcp_dport: 5432,
                          set: "app_servers",
                          counter: "pg_accepted"

        # -- Runtime services --
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 24}, udp_dport: 53

        nft_rule :drop, log_prefix: "DB-IN: ", counter: "input_drop"
      end

      # -- Outbound lockdown --
      base_chain "output", hook: :output, type: :filter,
                 priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, oifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, udp_dport: 53

        nft_rule :drop, log_prefix: "DB-OUT: ", counter: "output_drop"
      end
    end
  end
end
