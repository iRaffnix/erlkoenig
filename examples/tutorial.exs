defmodule Tutorial do
  use Erlkoenig.Stack

  # ═══════════════════════════════════════════════════════════════
  # Tutorial-Stack — zwei Tiers mit echter Isolation
  #
  #   IPVLAN L3S auf Dummy-Parent ek_tut (10.99.0.0/24)
  #
  #     10.99.0.1     Host-Side-Slave (Gateway aus Container-Sicht)
  #     10.99.0.2     web-0-echo    port 8080
  #     10.99.0.3     web-1-echo    port 8080
  #     10.99.0.4     api-0-echo    port 4000
  #
  #   Erlaubte Pfade:
  #     web → api:4000         (App-Call)
  #     Alle → Gateway         (DNS/Health via ICMP)
  #     Antworten              (ct_state established,related)
  #
  #   Blockiert (policy drop im Container-netns):
  #     api → web              (reverse: nie erlaubt)
  #     web → web              (Peer-Tier-Sprung: nie erlaubt)
  #
  # Starten:
  #   ek up examples/tutorial.exs
  # Inspizieren:
  #   ek ps
  #   ek pod list
  #   ek ct inspect web-0-echo
  # Runterfahren:
  #   ek down examples/tutorial.exs
  # ═══════════════════════════════════════════════════════════════

  pod "app", strategy: :one_for_one do

    container "web",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      zone: "tutorial",
      replicas: 2,
      restart: :permanent,
      limits: %{memory: 128_000_000, pids: 64} do

      # cgroup-Metriken alle 2s auf erlkoenig_events
      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      # stdout/stderr bei AMQP persistent (7 Tage)
      stream retention: {7, :days} do
        channel :stdout
        channel :stderr
      end

      # Firewall in eigener netns: wer reindarf, wer rausdarf
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, tcp_dport: 8080
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_daddr: {10, 99, 0, 4}, tcp_dport: 4000
          nft_rule :accept, ip_daddr: {10, 99, 0, 1}
        end
      end
    end

    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      zone: "tutorial",
      replicas: 1,
      restart: :transient,
      limits: %{memory: 256_000_000, pids: 128} do

      publish interval: 2000 do
        metric :memory
        metric :cpu
      end

      # api akzeptiert nur aus dem Web-Pool (.2, .3); alles
      # andere ist drop. Nach außen spricht api mit niemandem
      # außer Gateway (kein DB-Tier in diesem Tutorial).
      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_saddr: {10, 99, 0, 2}, tcp_dport: 4000
          nft_rule :accept, ip_saddr: {10, 99, 0, 3}, tcp_dport: 4000
        end

        output policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, ip_daddr: {10, 99, 0, 1}
        end
      end
    end
  end

  # ── Host ────────────────────────────────────────────────────────

  host do
    ipvlan "tutorial",
      parent: {:dummy, "ek_tut"},
      subnet: {10, 99, 0, 0, 24}

    nft_table :inet, "host" do
      nft_set "ban", :ipv4_addr

      nft_counter "input_drop"
      nft_counter "input_ban"

      base_chain "prerouting", hook: :prerouting, type: :filter,
        priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        # ── Standard-Härtung ──────────────────────────────
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22222          # SSH — sonst Lockout

        # ── Runtime-Services ──────────────────────────────
        # erlkoenig betreibt einen DNS-Resolver pro Zone auf der
        # Gateway-IP (10.99.0.1 hier). Ohne diese Regel timeoutet
        # jedes getaddrinfo() im Container. Magic-Inject gibt's
        # nicht — die Regel muss explizit dastehen.
        nft_rule :accept, ip_saddr: {10, 99, 0, 0, 24}, udp_dport: 53

        nft_rule :drop, counter: "input_drop", log_prefix: "HOST-DROP: "
      end
    end
  end

  # ── Guard: per-IP Threat-Actors ─────────────────────────────────

  guard do
    detect do
      flood over: 50, within: s(10)
      port_scan over: 20, within: m(1)
      honeypot [21, 22, 23, 445, 1433, 3306, 3389, 5900, 6379]
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
      {10, 99, 0, 1}
    ]
  end
end
