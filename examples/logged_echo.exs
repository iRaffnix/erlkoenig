defmodule LoggedEcho do
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════
  # Log Streaming — Container-Output über RabbitMQ Streams
  # ══════════════════════════════════════════════════════════
  #
  # Zeigt: stdout/stderr Streaming in RabbitMQ append-only Streams.
  # Replaybar, forensisch auswertbar, mit konfigurierbarer Retention.
  #
  # Voraussetzung:
  #   RabbitMQ mit rabbitmq_stream Plugin:
  #     rabbitmq-plugins enable rabbitmq_stream
  #
  # Starten:
  #   erlkoenig eval 'erlkoenig_config:load(<<"/tmp/logged_echo.term">>).'
  #
  # Live-Consumer:
  #   python3 tools/stream_consumer.py erlkoenig.log.echo-0-echo
  #
  # Nur stderr:
  #   python3 tools/stream_consumer.py erlkoenig.log.echo-0-echo --filter stderr
  #
  # Replay ab Anfang:
  #   python3 tools/stream_consumer.py erlkoenig.log.echo-0-echo --offset first
  #
  # Stream-Name: erlkoenig.log.<pod>-<replica>-<container>
  # Beide Kanäle (stdout + stderr) im selben Stream,
  # unterschieden durch headers.fd.
  #
  # Message Format:
  #   Body: rohe Bytes (kein JSON)
  #   Headers: fd, name, node, instance, seq, boot, wall_ts_ms
  #
  # Backpressure:
  #   1. atomics High-Watermark in forward_output (Drop vor Allokation)
  #   2. Bounded Queue im Publisher (max 1000 Chunks, Drop oldest)
  #   3. At-most-once — Container-I/O wird nie blockiert

  host do
    bridge "net", subnet: {10, 0, 0, 0, 24}

    nft_table :inet, "host" do
      nft_set "ban", :ipv4_addr
      nft_counter "input_drop"

      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do

        nft_rule :drop, set: "ban"
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22
        nft_rule :accept, tcp_dport: 9100
        nft_rule :drop, counter: "input_drop", log_prefix: "HOST: "
      end
    end
  end

  pod "echo", strategy: :one_for_one do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      limits: %{memory: 134_217_728, pids: 50},
      restart: :on_failure do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      # ── Log Stream ──────────────────────────────────────
      #
      # retention: wie lange Daten im RabbitMQ Stream bleiben.
      #   {7, :days} — eine Woche (Default)
      #   {90, :days} — drei Monate (für Forensik/Audit)
      #
      # max_bytes: optionale Größenobergrenze.
      #   {5, :gb} — max 5 GB pro Stream
      #
      # channel: welche File-Deskriptoren gestreamt werden.
      #   :stdout — stdout des Container-Prozesses
      #   :stderr — stderr des Container-Prozesses
      #
      # Ein Stream pro Container. Mehrere Inkarnationen (Restarts)
      # appenden in denselben Stream — unterscheidbar über
      # headers.instance (UUID) und headers.boot (Restart-Count).

      stream retention: {7, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end

  attach "echo", to: "net", replicas: 1
end
