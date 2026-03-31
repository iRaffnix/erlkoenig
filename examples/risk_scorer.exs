defmodule RiskScorer do
  @moduledoc """
  Risk scoring stack for the erlkoenig demo VM.

  Two container instances query PostgreSQL for customer risk assessment.
  BPF L4 load balancer distributes traffic across both.

  Network policy is explicit: containers can only reach DNS on the
  bridge and PostgreSQL on the gateway. No internet access.

  Deploy:
    erlkoenig compile examples/risk_scorer.exs
    ek:load("examples/risk_scorer.term")
  """

  use Erlkoenig.Stack

  # ── Images ───────────────────────────────────────────

  images do
    image "risk_scorer", path: "/var/lib/erlkoenig/images/risk_scorer.erofs"
  end

  # ── Network Zone + Containers ────────────────────────

  zone "apps",
    subnet: {10, 0, 0, 0},
    netmask: 24,
    pool: {{10, 0, 0, 10}, {10, 0, 0, 250}} do

    # Network policy: explicit, deny-by-default
    allow :dns                          # containers can resolve names
    allow :gateway, ports: [5432]       # containers can reach PG on host

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
