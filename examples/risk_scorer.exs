defmodule RiskScorer do
  @moduledoc """
  Risk scoring stack for the erlkoenig demo VM.

  Two container instances behind a BPF L4 load balancer,
  each querying PostgreSQL for customer risk assessment.

  Deploy:
    erlkoenig compile examples/risk_scorer.exs
    ek:load("examples/risk_scorer.term")
  """

  use Erlkoenig.Stack

  # ── Images ───────────────────────────────────────────

  images do
    image "risk_scorer", path: "/tmp/risk_scorer.erofs"
  end

  # ── Host Firewall ────────────────────────────────────

  # firewall "host" do
  #   counters [:ssh, :http, :pg, :dropped]
  #
  #   set "blocklist", :ipv4_addr, timeout: 3_600_000
  #
  #   chain "inbound", hook: :input, policy: :drop do
  #     accept :established
  #     accept :loopback
  #     accept :icmp
  #     accept_tcp 22, counter: :ssh
  #     accept_tcp 8080, counter: :http
  #     accept_subnet_port {10, 0, 0, 0}, 24, :tcp, 5432, counter: :pg
  #     drop_if_in_set "blocklist"
  #     log_and_drop "DROP: ", counter: :dropped
  #   end
  #
  #   chain "forward", hook: :forward, priority: -10, policy: :drop do
  #     accept :established
  #     accept_on_interface "vh_*"
  #     accept_output_interface "vh_*"
  #   end
  # end

  # ── Network Zone + Containers ────────────────────────

  zone "apps",
    subnet: {10, 0, 0, 0},
    gateway: {10, 0, 0, 1},
    netmask: 24 do

    container "scorer-1",
      image: "risk_scorer",
      binary: "/app",
      ip: {10, 0, 0, 10},
      limits: %{memory: 64_000_000, pids: 50},
      restart: :always do

      env "PG_HOST", "10.0.0.1"
      env "PG_PORT", "5432"
      env "PG_DB", "erlkoenig"
      env "PG_USER", "ek"
    end

    container "scorer-2",
      image: "risk_scorer",
      binary: "/app",
      ip: {10, 0, 0, 11},
      limits: %{memory: 64_000_000, pids: 50},
      restart: :always do

      env "PG_HOST", "10.0.0.1"
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
    # {10, 0, 0, 1} auto-whitelisted (zone gateway)
  end
end
