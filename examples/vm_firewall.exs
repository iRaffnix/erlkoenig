defmodule VmFirewall do
  @moduledoc """
  Host firewall for the erlkoenig demo VM (erlkoenig-2).

  Interface layout:
    eth0              178.104.17.63  — public internet
    enp7s0            10.20.30.3     — private Hetzner network
    erlkoenig_br0     10.0.0.1       — container bridge

  Deploy:
    erlkoenig compile examples/vm_firewall.exs
    ek:load("examples/vm_firewall.term")
  """

  use Erlkoenig.Stack

  firewall "host" do
    counters [:ssh, :http, :pg, :dropped, :banned]

    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    # ── Input: protect the host ────────────────────────

    chain "inbound", hook: :input, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "lo"
      rule :accept, icmp: true

      # SSH — rate limited
      rule :accept, tcp: 22, limit: {25, burst: 5}, counter: :ssh

      # Gateway HTTP API
      rule :accept, tcp: 8080, counter: :http

      # PostgreSQL — only from container subnet
      rule :accept, tcp: 5432, saddr: {10, 0, 0, 0, 24}, counter: :pg

      # EPMD — only localhost
      rule :accept, tcp: 4369, iif: "lo"

      # Blocklists
      rule :drop, set: "blocklist", counter: :banned

      # Default: log + drop
      rule :drop, log: "HOST_DROP: ", counter: :dropped
    end

    # ── Forward: container traffic ─────────────────────
    # Priority -10: runs BEFORE erlkoenig_ct (priority 0)

    chain "forward", hook: :forward, priority: -10, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "vh_*"
      rule :accept, oif: "vh_*"
    end

    # ── Postrouting: NAT for containers ────────────────

    chain "postrouting", hook: :postrouting, type: :nat, policy: :accept do
      rule :masquerade, oif_neq: "erlkoenig_br0"
    end
  end

  # ── Threat Detection ─────────────────────────────────

  guard do
    detect :conn_flood, threshold: 200, window: 10
    detect :port_scan, threshold: 30, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
    whitelist {10, 0, 0, 1}
    whitelist {10, 20, 30, 3}
  end
end
