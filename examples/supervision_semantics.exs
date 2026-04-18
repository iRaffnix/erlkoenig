defmodule SupervisionSemantics do
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════
  # Supervision Semantics — fail-closed networking, crashloop
  # quarantine, and bounded-concurrency admission control.
  # ══════════════════════════════════════════════════════════
  #
  # This example exists to make the three recent OTP-level
  # features visible:
  #
  #   1. Fail-closed firewall.  The erlkoenig_nft_firewall worker
  #      is marked `significant` in its supervisor subtree, and
  #      the root supervisor is configured with `auto_shutdown =>
  #      any_significant`. If the firewall dies beyond its own
  #      restart intensity, the BEAM terminates cleanly — systemd
  #      restarts the whole app, and containers refuse to run
  #      while there is no enforced network policy.
  #
  #      There is nothing to configure from the DSL: the flag is
  #      a product-level invariant. Operators who want to override
  #      it do so in sys.config, not here.
  #
  #   2. Crashloop quarantine.  If a container's binary (identified
  #      by SHA-256) crashes N times in M seconds (defaults: 5 in
  #      60 s), the hash is placed in a memory-resident quarantine
  #      list. The next spawn for that hash is refused with an
  #      explicit `{quarantined, Hash, Since}` reason. The
  #      container shows up as `state: :failed` in `inspect/1`
  #      with a clear error_reason.
  #
  #      Tune via sys.config:
  #
  #        {quarantine_threshold, 5}
  #        {quarantine_window_ms, 60000}
  #
  #      AMQP: `security.<hash-prefix>.quarantined` fires on entry.
  #
  #   3. Admission gate.  At most N container spawns can be
  #      mid-setup at the same time (defaults: 10 on the host,
  #      unlimited per zone). Bursty deployments queue rather than
  #      thrash the C runtime. Timeouts and queue overflows fail
  #      the spawn cleanly.
  #
  #      Tune via sys.config:
  #
  #        {admission_max_host,           10}
  #        {admission_max_per_zone,        0}   %% 0 = disabled
  #        {admission_queue_limit,       100}
  #        {admission_acquire_timeout_ms, 30000}
  #
  # The stack below just demonstrates a normal hardened
  # deployment; the three features apply to every container.

  host do
    ipvlan "app-net",
      parent: {:dummy, "ek_app"},
      subnet: {10, 0, 0, 0, 24}

    nft_table :inet, "host" do
      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do
        # ── Standard-Härtung ──────────────────────────────
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, tcp_dport: 22

        # ── Runtime-Services ──────────────────────────────
        # erlkoenig DNS-Resolver pro Zone auf der Gateway-IP.
        # Ohne diese Regel timeoutet jedes getaddrinfo() im
        # Container. Glasbox: explizit, kein Magic-Inject
        # (Kapitel 6 Service-Catalogue).
        nft_rule :accept, ip_saddr: {10, 0, 0, 0, 24}, udp_dport: 53
      end
    end
  end

  pod "app", strategy: :one_for_one do
    container "svc",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      args: ["600"],
      zone: "app-net",
      replicas: 3,
      restart: :permanent do

      volume "/data", persist: "svc-data"
    end
  end
end
