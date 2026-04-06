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

    # ── Host-Firewall (Referenz) ─────────────────────────────
    #
    # Schützt den Host selbst — nicht die Container (die haben
    # eigene Forward-Regeln im "erlkoenig" Table).
    #
    # hook: :input — Pakete die AN den Host adressiert sind
    #                (nicht forwarded, nicht an Container)
    # policy: :drop — alles was keine Regel matcht → verworfen
    # priority: :filter — Standard-Priorität (0)
    #
    # Reihenfolge ist entscheidend: nft evaluiert top-to-bottom,
    # erste matchende Regel gewinnt.

    nft_table :inet, "host" do

      # ── Sets ─────────────────────────────────────────────
      # Ban-Set: wird vom Guard automatisch gefüllt.
      # IPs hier drin werden VOR connection tracking gedroppt —
      # null conntrack Entries, null NAT Lookups, null CPU.
      nft_set "ban", :ipv4_addr

      # ── Counters ─────────────────────────────────────────
      # Jeder Counter wird alle 2s gepollt.
      # Rate > 0 → AMQP Event: firewall.input.drop
      nft_counter "input_drop"
      nft_counter "input_ban"

      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        # ┌─────────────────────────────────────────────────┐
        # │ 1. BAN SET — vor allem anderen                  │
        # │                                                 │
        # │ Gebannte IPs erzeugen KEINEN conntrack Entry.   │
        # │ Kein NAT Lookup, kein State, kein Log.          │
        # │ Das ist der schnellste Weg ein Paket zu droppen.│
        # └─────────────────────────────────────────────────┘
        nft_rule :drop, set: "ban", counter: "input_ban"

        # ┌─────────────────────────────────────────────────┐
        # │ 2. CONNECTION TRACKING                          │
        # │                                                 │
        # │ Antworten auf Verbindungen die der Host selbst  │
        # │ initiiert hat (AMQP → RabbitMQ, DNS, apt, NTP).│
        # │ Ohne diese Regel sterben Antworten am Drop.    │
        # │                                                 │
        # │ :established — TCP ACK/PSH/FIN auf offene Conn  │
        # │ :related — ICMP errors die zu einer Conn gehören│
        # └─────────────────────────────────────────────────┘
        nft_rule :accept, ct_state: [:established, :related]

        # ┌─────────────────────────────────────────────────┐
        # │ 3. LOOPBACK                                     │
        # │                                                 │
        # │ localhost, epmd (4369), Erlang Distribution,    │
        # │ BEAM-interne Kommunikation. Ohne das geht       │
        # │ erlkoenig eval / ping / remote_console nicht.   │
        # └─────────────────────────────────────────────────┘
        nft_rule :accept, iifname: "lo"

        # ┌─────────────────────────────────────────────────┐
        # │ 4. ICMP — Ping                                  │
        # │                                                 │
        # │ Monitoring (Nagios/Zabbix/Uptime), Debugging,   │
        # │ Path-MTU-Discovery. ICMP komplett zu blocken    │
        # │ bricht Netzwerk-Diagnostik.                     │
        # └─────────────────────────────────────────────────┘
        nft_rule :accept, ip_protocol: :icmp

        # ┌─────────────────────────────────────────────────┐
        # │ 5. SSH — Fernzugriff                            │
        # │                                                 │
        # │ Port 22. Für stärkere Absicherung:              │
        # │ - Key-only (PasswordAuthentication no)          │
        # │ - fail2ban oder Guard mit conn_flood Detection  │
        # │ - Optional: ip_saddr für IP-Whitelist           │
        # └─────────────────────────────────────────────────┘
        nft_rule :accept, tcp_dport: 22

        # ┌─────────────────────────────────────────────────┐
        # │ 6. PROMETHEUS — Node-Exporter                   │
        # │                                                 │
        # │ Port 9100. Prometheus scrapt CPU, RAM, Disk.    │
        # │ Wenn kein Prometheus: Zeile entfernen.          │
        # └─────────────────────────────────────────────────┘
        nft_rule :accept, tcp_dport: 9100

        # ┌─────────────────────────────────────────────────┐
        # │ 7. DEFAULT DROP                                 │
        # │                                                 │
        # │ Alles was bis hier nicht gematcht hat.           │
        # │ Counter zählt Drops (sichtbar über AMQP).       │
        # │ Log-Prefix für NFLOG Paket-Details.             │
        # │                                                 │
        # │ In Production: log_prefix weglassen wenn laut.  │
        # └─────────────────────────────────────────────────┘
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
