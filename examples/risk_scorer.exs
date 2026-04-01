defmodule RiskScorer do
  @moduledoc """
  Risk scoring stack for the erlkoenig demo VM.

  Two container instances query PostgreSQL for customer risk assessment.
  BPF L4 load balancer distributes traffic across both.

  Deploy:
    erlkoenig compile examples/risk_scorer.exs
    ek:load("examples/risk_scorer.term")
  """

  use Erlkoenig.Stack

  # ── Images ───────────────────────────────────────────

  images do
    image "risk_scorer", path: "/var/lib/erlkoenig/images/risk_scorer.erofs"
  end

  # ── Host Firewall ────────────────────────────────────

  firewall "host" do
    counters [:ssh, :http, :pg, :dropped, :banned]

    set "blocklist", :ipv4_addr, timeout: 3_600_000
    set "blocklist6", :ipv6_addr, timeout: 3_600_000

    chain "inbound", hook: :input, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "lo"
      rule :accept, icmp: true
      rule :accept, tcp: 22, counter: :ssh, limit: {25, burst: 5}
      rule :accept, tcp: 8080, counter: :http
      rule :drop, set: "blocklist", counter: :banned
      rule :drop, log: "HOST_DROP: ", counter: :dropped
    end

    chain "forward", hook: :forward, priority: -10, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "vh_*"
      rule :accept, oif: "vh_*"
    end

    chain "postrouting", hook: :postrouting, type: :nat, policy: :accept do
      rule :masquerade, oif_neq: "erlkoenig_br0"
    end
  end

  # ── Network Zone + Containers ────────────────────────

  zone "apps",
    subnet: {10, 0, 0, 0},
    netmask: 24,
    pool: {{10, 0, 0, 10}, {10, 0, 0, 250}} do

    allow :dns
    allow :gateway, ports: [5432]

    container "scorer-1",
      image: "risk_scorer",
      binary: "/app",
      restart: :always,
      limits: %{memory: 64_000_000, pids: 50} do

      env "PG_HOST", "gateway.erlkoenig"
      env "PG_PORT", "5432"
      env "PG_DB", "erlkoenig"
      env "PG_USER", "ek"
    end

    container "scorer-2",
      image: "risk_scorer",
      binary: "/app",
      restart: :always,
      limits: %{memory: 64_000_000, pids: 50} do

      env "PG_HOST", "gateway.erlkoenig"
      env "PG_PORT", "5432"
      env "PG_DB", "erlkoenig"
      env "PG_USER", "ek"
    end
  end

  # ── BPF Steering ─────────────────────────────────────

  steering do
    service :risk_scorer,
      vip: {10, 0, 0, 100},
      port: 8080,
      proto: :tcp,
      backends: ["scorer-1", "scorer-2"]
  end

  # ── Threat Detection ─────────────────────────────────

  guard do
    detect :conn_flood, threshold: 200, window: 10
    detect :port_scan, threshold: 30, window: 60
    ban_duration 3600
    whitelist {127, 0, 0, 1}
  end
end
