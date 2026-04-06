defmodule SimpleEcho do
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════
  # Minimal Example — ein einzelner Container
  # ══════════════════════════════════════════════════════════
  #
  # Zeigt: Bridge, Pod, Container, Metrics, Log Streaming.
  # Keine Firewall, keine PKI, keine Multi-Tier-Topologie.
  #
  # Starten:
  #   mix run -e '
  #     [{mod, _}] = Code.compile_file("examples/simple_echo.exs")
  #     mod.write!("/tmp/simple_echo.term")
  #   '
  #   erlkoenig eval 'erlkoenig_config:load(<<"/tmp/simple_echo.term">>).'
  #
  # Beobachten:
  #   python3 tools/event_consumer.py <rabbitmq-host> "#"
  #   python3 tools/stream_consumer.py erlkoenig.log.echo-0-echo

  # ── Topologie ────────────────────────────────────────────
  #
  # Eine Bridge = ein Layer-2 Segment.
  # subnet: IPv4 CIDR — Gateway wird .1, IP-Pool .2-.254.

  host do
    bridge "echo", subnet: {10, 0, 0, 0, 24}

    # ── Host-Firewall ──────────────────────────────────────
    #
    # nft_set "ban": IP-Adressen die sofort gedroppt werden —
    # BEVOR connection tracking. Gebannte IPs erzeugen null
    # Kernel-State (kein conntrack Entry, kein NAT Lookup).
    # Der Guard füllt das Set automatisch bei Flood/Scan.

    # ── Host-Firewall ──────────────────────────────────────
    #
    # Schützt den Host (nicht die Container — die haben
    # eigene Forward-Regeln). Reihenfolge ist wichtig:
    #
    #   1. Ban-Set: gebannte IPs sofort droppen (vor ct)
    #   2. ct established: Antworten auf eigene Verbindungen
    #   3. Loopback: localhost, epmd, Erlang Distribution
    #   4. ICMP: Ping erlauben (Monitoring, Debugging)
    #   5. SSH: Fernzugriff
    #   6. Prometheus: Node-Exporter Metriken (optional)
    #   7. Default Drop + Log

    nft_table :inet, "host" do
      nft_set "ban", :ipv4_addr
      nft_counter "input_drop"

      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        # Gebannte IPs: sofort weg, null Kernel-State
        nft_rule :drop, set: "ban"

        # Bestehende Verbindungen: Antworten durchlassen
        nft_rule :accept, ct_state: [:established, :related]

        # Loopback: BEAM-interne Kommunikation
        nft_rule :accept, iifname: "lo"

        # ICMP: Ping für Monitoring
        nft_rule :accept, ip_protocol: :icmp

        # SSH: Fernzugriff
        nft_rule :accept, tcp_dport: 22

        # Prometheus Node-Exporter (Port 9100)
        nft_rule :accept, tcp_dport: 9100

        # Alles andere: droppen + zählen
        nft_rule :drop, counter: "input_drop", log_prefix: "HOST: "
      end
    end
  end

  # ── Container ────────────────────────────────────────────
  #
  # pod: Gruppe von Containern mit gemeinsamer Supervision.
  #   strategy: :one_for_one — jeder Container restartet unabhängig
  #             :one_for_all — einer crasht, alle restarten
  #             :rest_for_one — crash restartet alle nachfolgenden
  #
  # container: ein Linux-Prozess in eigenem Namespace.
  #   binary: Pfad zum statischen Binary (absolute)
  #   args: Kommandozeilen-Argumente
  #   restart: Wann neustarten bei Exit
  #     :no_restart — nie (default)
  #     :always — bei jedem Exit
  #     :on_failure — bei non-zero Exit
  #     {:on_failure, N} — max N Versuche

  pod "echo", strategy: :one_for_one do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      restart: :on_failure do

      # ── cgroup Metrics ─────────────────────────────────
      #
      # publish: periodische cgroup-Metriken über AMQP.
      # interval: Polling-Intervall in Millisekunden (min: 1000).
      # metric: welche cgroup-Dateien gelesen werden.
      #
      # AMQP Routing Keys:
      #   stats.echo-0-echo.memory  (current, peak, max, pct, swap)
      #   stats.echo-0-echo.cpu     (usec, delta_usec, throttled)
      #   stats.echo-0-echo.pids    (current, max)
      #   stats.echo-0-echo.pressure (PSI: cpu/memory/io avg10)
      #   stats.echo-0-echo.oom     (kills, events)

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      publish interval: 10_000 do
        metric :pressure
        metric :oom_events
      end

      # ── Log Streaming ──────────────────────────────────
      #
      # stream: stdout/stderr in RabbitMQ Stream (append-only).
      # retention: wie lange Daten im Stream bleiben.
      # channel: welche File-Deskriptoren gestreamt werden.
      #   :stdout — Container stdout
      #   :stderr — Container stderr
      # Beide landen im selben Stream (erlkoenig.log.<name>),
      # unterschieden durch headers.fd.

      stream retention: {7, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end

  # ── Deployment ───────────────────────────────────────────
  #
  # attach: verbindet Pod mit Bridge.
  #   to: Bridge-Name
  #   replicas: Anzahl Instanzen
  #
  # Erzeugt: echo-0-echo (IP 10.0.0.2)
  # Bei replicas: 3 → echo-0-echo, echo-1-echo, echo-2-echo

  attach "echo", to: "echo", replicas: 1
end
