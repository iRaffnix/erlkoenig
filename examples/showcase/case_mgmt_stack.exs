defmodule CaseMgmtStack do
  @moduledoc """
  Reference task-tracker stack — postgres + journal walking skeleton.

  A full-stack workload that drives two service capabilities at once:

    - `:postgres.local` — task metadata, notes, deadlines, time entries
    - `:journal.local` — audit-trail for every mutation
                         (chain-verifiable end-to-end)

  Phase 2 ideas (see `project_per_tenant_crypto` memory):

    - Per-tenant SQLCipher files under `:tenant.local`
    - `:keystore.local` for crypto-shred-able key custody

  The Go binary `examples/agents/case_mgmt` exposes a tiny HTTP API on :8080:

      POST /tasks                   {title, description}  → INSERT, 201
      GET  /tasks/:id                                     → task + timeline
      POST /tasks/:id/notes         {body}                → INSERT note
      GET  /tasks?q=<substring>                           → search by title

  Every mutation writes one `:journal.local` entry; the audit chain
  signs + seals it. An external Go verifier (book ch20) can later
  re-run the chain offline for compliance proof.
  """
  use Erlkoenig.Stack

  host do
    ipvlan "ops", parent: {:dummy, "ek_ops"}, subnet: {10, 70, 0, 0, 24}

    # ── Host firewall ──────────────────────────────────────────
    #
    # Containers reach two node-resident services: the Erlang DNS
    # resolver on the zone gateway AND Postgres on the bind-mounted
    # Unix socket. The socket needs no nft rule (it's not network).
    # The DNS one does — we write it here explicitly. No magic
    # injection: operator owns the host firewall.
    nft_host do
      nft_set "ban", :ipv4_addr
      nft_counter "input_drop"
      nft_counter "input_ban"

      base_chain "prerouting", hook: :prerouting, type: :filter,
        priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22     # SSH
        nft_rule :accept, tcp_dport: 8080   # case_mgmt HTTP API (from host)

        # ── Runtime services — mirrors the `requires` lines in
        # each container block. If we forget this, the container's
        # DNS resolution silently breaks. No magic injection: that
        # is the point.
        nft_rule :accept, ip_saddr: {10, 70, 0, 0, 24}, udp_dport: 53

        nft_rule :drop, counter: "input_drop", log_prefix: "HOST: "
      end
    end
  end

  # ── Pod: case_mgmt ──────────────────────────────────────────
  #
  # One container for the walking skeleton. Scaling to multiple
  # replicas works when we add per-container role isolation in the
  # `:postgres.local` runtime (phase 2). For now: single writer,
  # single role, single tenant.

  pod "case_mgmt", strategy: :one_for_one do
    container "agent",
      binary: "/opt/erlkoenig/rt/demo/case_mgmt",
      zone: "ops",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 256_000_000, pids: 128} do

      # ── Service capabilities ────────────────────────────────
      # These declarations are the whole grant surface.
      # The DSL injects env vars + bind-mounts; the runtime
      # enforces the mount namespace. No per-container creds,
      # no SCRAM password — Postgres peer-auth over the
      # bind-mounted socket authenticates by uid.
      requires :"postgres.local"
      requires :"journal.local"
      requires :"dns.local"

      # SPEC-AS-009 L7 egress: only these hosts resolve. Any other
      # name the workload tries to look up gets NXDOMAIN and lands
      # in the audit chain. L4 reachability is still controlled by
      # the `nft output` block below — capabilities add, don't
      # replace, operator-owned firewall.
      requires :"dns.allowlist",
        hosts: [
          "*.postgres.internal",
          "audit.erlkoenig.internal"
        ]

      # ── cgroup publish — standard observability ─────────────
      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      # ── Log stream (stdout/stderr → AMQP) ───────────────────
      stream retention: {30, :days} do
        channel :stdout
        channel :stderr
      end

      # ── Container firewall: outbound to Postgres on gateway,
      # inbound 8080 from anywhere (real deployment would front
      # this with a WireGuard-terminated reverse proxy).
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, tcp_dport: 8080
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          # Talk to zone gateway (DNS) - postgres.local goes via
          # the Unix socket bind-mount, not through the network,
          # so nothing extra needed there.
          nft_rule :accept, ip_daddr: {10, 70, 0, 1}
        end
      end
    end
  end

  # ── Threat detection ─────────────────────────────────────────
  #
  # Internal task data attracts attention too — bans are cheap to enforce.

  guard do
    detect do
      flood over: 50, within: s(10)
      port_scan over: 20, within: m(1)
      slow_scan over: 5, within: h(1)
      # SSH is explicitly allowed by the host firewall above, so keep
      # tcp/22 out of the honeypot set to avoid operator lockout.
      honeypot [21, 23, 445, 1433, 1521, 3306, 3389, 5900, 6379]
    end

    respond do
      suspect after: 3, distinct: :ports
      ban_for h(1)
      honeypot_ban_for h(24)
      escalate [h(1), h(6), h(24), d(7)]
      observe_after_unban m(2)
      forget_after m(5)
    end

    allowlist [
      {127, 0, 0, 1},
      {10, 70, 0, 1}
    ]
  end
end
