defmodule LiveLabs.FirewallHostCounters do
  @moduledoc """
  Host-firewall counter lab.

  Expected operator signals:

    * `ek config validate` accepts the firewall-only DSL
    * `ek up --allow-lockout` applies the host-owned nft table
    * `ek up` shows the nft table summary and apply-ok line
    * journalctl shows the runtime adoption line for `erlkoenig_host`
    * `ek nft counters` shows `live_ssh_accept` and `live_input_drop`
    * repeated SSH/operator commands increment `live_ssh_accept`
    * `ek firewall events` shows canonical firewall counter events once rates are non-zero

  Safety:

    This lab keeps SSH explicitly open, accepts established traffic, accepts
    loopback and ICMP, and does not define an output chain.

  Operator loop:

      /opt/erlkoenig/bin/ek dsl compile examples/live_labs/10_firewall_host_counters.exs -o /tmp/ek_live_lab_10.term
      /opt/erlkoenig/bin/ek config validate /tmp/ek_live_lab_10.term
      /opt/erlkoenig/bin/ek --allow-lockout up /tmp/ek_live_lab_10.term
      /opt/erlkoenig/bin/ek nft counters
      /opt/erlkoenig/bin/ek firewall events --limit 10
  """
  use Erlkoenig.Stack

  host do
    nft_host do
      nft_counter "live_ssh_accept"
      nft_counter "live_input_drop"

      base_chain "input",
        hook: :input,
        type: :filter,
        priority: :filter,
        policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22, counter: "live_ssh_accept"

        nft_rule :drop, counter: "live_input_drop"
      end
    end
  end
end
