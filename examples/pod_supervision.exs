defmodule PodSupervision do
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════
  # Pod Supervision Strategies
  # ══════════════════════════════════════════════════════════
  #
  # Zeigt die drei OTP Supervision-Strategien für Container:
  #
  #   :one_for_one   — jeder Container restartet unabhängig
  #   :one_for_all   — einer crasht → alle restarten
  #   :rest_for_one  — einer crasht → er + alle danach restarten
  #
  # Testen:
  #   # Welcher Container restartet bei Crash?
  #
  #   kill -9 <os_pid von coupled-0-cache>
  #     → coupled-0-app restartet auch (one_for_all)
  #
  #   kill -9 <os_pid von pipeline-0-transform>
  #     → pipeline-0-export restartet (rest_for_one)
  #     → pipeline-0-ingest bleibt (war vor transform)
  #
  #   kill -9 <os_pid von workers-0-fn>
  #     → nur workers-0-fn restartet (one_for_one)

  host do
    bridge "compute", subnet: {10, 0, 0, 0, 24}

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

  # ── :one_for_all — gekoppelte Container ──────────────────
  #
  # App + Cache gehören zusammen. Wenn Cache crasht muss
  # auch App neu starten (weil App cached State hat).

  pod "coupled", strategy: :one_for_all do
    container "app",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      limits: %{memory: 268_435_456, pids: 100},
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      stream retention: {7, :days} do
        channel :stderr
      end
    end

    container "cache",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["6379"],
      limits: %{memory: 134_217_728, pids: 50},
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :pids
      end

      stream retention: {7, :days} do
        channel :stderr
      end
    end
  end

  # ── :rest_for_one — Pipeline mit Abhängigkeitskette ──────
  #
  # Reihenfolge ist wichtig: ingest → transform → export.
  # Wenn transform crasht, muss export auch neu starten
  # (weil export von transform's Output abhängt).
  # Aber ingest läuft weiter (ist upstream).

  pod "pipeline", strategy: :rest_for_one do
    container "ingest",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9001"],
      limits: %{memory: 268_435_456, pids: 100},
      restart: :always do

      publish interval: 5000 do
        metric :memory
        metric :cpu
      end

      publish interval: 30_000 do
        metric :pressure
      end

      stream retention: {30, :days} do
        channel :stdout
        channel :stderr
      end
    end

    container "transform",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9002"],
      limits: %{memory: 536_870_912, pids: 200},
      restart: :always do

      publish interval: 5000 do
        metric :memory
        metric :cpu
      end

      stream retention: {30, :days} do
        channel :stderr
      end
    end

    container "export",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9003"],
      limits: %{memory: 268_435_456, pids: 100},
      restart: :always do

      publish interval: 5000 do
        metric :memory
        metric :cpu
      end

      stream retention: {30, :days} do
        channel :stderr
      end
    end
  end

  # ── :one_for_one — unabhängige Worker ────────────────────
  #
  # Jeder Worker ist austauschbar. Crash eines Workers
  # hat keine Auswirkung auf andere.

  pod "workers", strategy: :one_for_one do
    container "fn",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7000"],
      limits: %{memory: 134_217_728, pids: 50},
      restart: {:on_failure, 3} do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      publish interval: 10_000 do
        metric :pressure
        metric :oom_events
      end

      stream retention: {7, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end

  attach "coupled",  to: "compute", replicas: 1
  attach "pipeline", to: "compute", replicas: 1
  attach "workers",  to: "compute", replicas: 2
end
