defmodule Tutorial.ThreatDetection do
  @moduledoc """
  ### Datei 4/6 — Reactive Firewall / Threat-Detection (SPEC-EK-020)

  `guard` ist die deklarative Schnittstelle zum per-IP Threat-Actor
  Subsystem. Pro verdächtiger Quell-IP läuft ein `gen_statem` (ein
  Erlang-Prozess) der Zustand für diese IP hält — kein
  gemeinsamer Shared-State, kein Scheduler-Overhead bei inaktiven
  IPs (kein Prozess existiert für harmlose IPs).

  Zwei Blöcke innerhalb `guard`:
    * `detect` — welche Verhalten zählen als verdächtig
    * `respond` — wie reagiert wird (suspect → ban → escalate)
    * `allowlist` — IPs die NIE geban't werden (monitoring, NOC)

  Wichtig: guard setzt auf conntrack-events + NFLOG-Drop-Events
  auf, die host-firewall MUSS konfiguriert sein damit das System
  was zum "sehen" hat. Siehe `nft_rule :drop, counter: ...,
  log_prefix: ...` Pattern in Datei 3.

  Zeit-Helper im Guard:
    * `s(N)` — N seconds
    * `m(N)` — N minutes
    * `h(N)` — N hours
    * `d(N)` — N days

  Die werden durch `use Erlkoenig.Stack` automatisch importiert.
  """
  use Erlkoenig.Stack

  host do
    ipvlan "edge", parent: {:dummy, "ek_edge"},
                   subnet: {10, 40, 0, 0, 24}

    nft_host do
      nft_set "ban", :ipv4_addr
      nft_counter "input_drop"
      nft_counter "input_ban"
      nft_counter "honeypot_hits"

      # Raw-prerouting — gebannte IPs sterben VOR conntrack.
      base_chain "prerouting_raw", hook: :prerouting, type: :filter,
                 priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      base_chain "input", hook: :input, type: :filter,
                 priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp

        # Legit services
        nft_rule :accept, tcp_dport: 22
        nft_rule :accept, tcp_dport: 443

        # Default-drop MIT log_prefix — ohne den Prefix hat der
        # threat-actor nichts zum Korrelieren. Der Prefix wandert
        # via NFLOG-group in die erlkoenig_nft_nflog → ct_events
        # pg-broadcast → threat_actor handle_info-Chain.
        nft_rule :drop, counter: "input_drop",
                        log_prefix: "HOST: "
      end
    end
  end

  # ══════════════════════════════════════════════════════════════════
  # GUARD — das Herzstück der Reactive Firewall
  # ══════════════════════════════════════════════════════════════════
  guard do

    # ────────────────────────────────────────────────────────────────
    # DETECT — welche Verhaltensmuster triggern den state-machine?
    # ────────────────────────────────────────────────────────────────
    detect do

      # Packet-Flood: > N Pakete innerhalb X Zeit vom gleichen src.
      # Typisches Muster: SYN-flood, UDP-amplifier-scans.
      flood over: 50, within: s(10)

      # Port-Scan: N verschiedene Ports innerhalb kurzer Zeit
      # gescannt. nmap & Freunde. Der Counter ist "distinct ports",
      # nicht "total drops".
      port_scan over: 20, within: m(1)

      # Slow-Scan: der gemeine Typ. Angreifer probiert langsam,
      # um unter Flood- und Port-Scan-Thresholds zu bleiben. Über
      # eine Stunde 5 distinct ports = höchstwahrscheinlich bösartig.
      slow_scan over: 5, within: h(1)

      # Honeypot-Ports. Jeder Connect auf diese Ports triggert
      # SOFORT Ban (kein Counter, keine Schwelle). Port 22 ist
      # hier drin WENN real-SSH auf anderem Port lebt; 3389/5900
      # sind nie gute Enden auf einem linux-server; 445/1433/1521
      # sind windows-Protokoll-Scans; 6379 ist Redis-ohne-auth-Scan.
      #
      # WICHTIG: Ports die als Honeypot markiert sind dürfen NICHT
      # im nft-INPUT als accept stehen — sonst landen legitime
      # Verbindungen im Honeypot-Ban. Die ports müssen gedropt
      # werden DAMIT der drop im NFLOG landet und den threat-actor
      # triggert.
      honeypot [21, 23, 445, 1433, 1521, 3306, 3389, 5900, 6379]
    end

    # ────────────────────────────────────────────────────────────────
    # RESPOND — wie reagiert das State-Machine?
    # ────────────────────────────────────────────────────────────────
    respond do

      # Erst bei N distinct:<what> auffälligkeiten wird die IP
      # überhaupt zum "suspect". Vorher: harmlose Statistik.
      # `distinct: :ports` = N verschiedene Ports angegangen.
      # `distinct: :destinations` = N verschiedene Ziel-IPs.
      suspect after: 3, distinct: :ports

      # Normal-Ban: Standard-Dauer nach Detect-Hit.
      ban_for h(1)

      # Honeypot-Ban: deutlich härter als normal, weil das
      # Verhalten eindeutig böswillig ist.
      honeypot_ban_for h(24)

      # Escalation-Ladder: wenn eine IP nach Ablauf des Bans
      # SOFORT wieder auffällt, verdoppelt sich die Strafe.
      # Die Liste ist strict aufsteigend.
      escalate [h(1), h(6), h(24), d(7)]

      # Nach Unban: die IP bleibt N Minuten im "observe"-State —
      # jeder weitere Detect-Hit innerhalb des Observe-Windows
      # löst den nächsten Escalation-Step aus, OHNE den normalen
      # suspect-Threshold durchlaufen zu müssen.
      observe_after_unban m(2)

      # Wenn eine IP N Minuten komplett ruhig war, vergisst das
      # State-Machine sie (Prozess wird beendet, Zustand weg).
      # Damit die Escalation-Ladder nicht forever-memory frisst.
      forget_after m(5)
    end

    # ────────────────────────────────────────────────────────────────
    # ALLOWLIST — diese IPs werden NIE geban't
    # ────────────────────────────────────────────────────────────────
    #
    # Monitoring, Health-Checker, Deploy-Agents, NOC, deine eigene
    # IP. Unbedingt hier: alles was regulär aggressive Patterns
    # zeigt ohne böswillig zu sein (Port-Scanner für inventory,
    # Nagios der alle paar Sekunden checkt, …).
    #
    # Loopback und das Zone-Gateway sind Pflicht — sonst kann
    # dein eigenes BEAM sich selbst bannen.
    allowlist [
      {127, 0, 0, 1},
      {10, 40, 0, 1}
    ]
  end

  # ══════════════════════════════════════════════════════════════════
  # Minimaler Pod — nur damit das File lauffähig ist
  # ══════════════════════════════════════════════════════════════════
  pod "edge", strategy: :one_for_one do
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["443"],
      zone: "edge",
      replicas: 1,
      restart: :permanent,
      limits: %{memory: 256_000_000, pids: 128} do

      nft do
        input policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, ip_protocol: :icmp
          nft_rule :accept, tcp_dport: 443
        end
      end
    end
  end
end
