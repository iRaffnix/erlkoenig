defmodule PodSupervision do
  use Erlkoenig.Stack

  # ── Pod Supervision Strategies ────────────────────────
  #
  # Demonstrates all three pod supervision modes:
  #
  #   :one_for_one  (default) — each container restarts independently
  #   :one_for_all           — one crashes, all restart
  #   :rest_for_one          — one crashes, it + later siblings restart
  #
  # Test by killing a container and observing which others restart:
  #
  #   kill -9 <os_pid of coupled-0-cache>
  #     → coupled-0-app also restarts (one_for_all)
  #
  #   kill -9 <os_pid of pipeline-0-transform>
  #     → pipeline-0-export restarts, pipeline-0-ingest stays (rest_for_one)
  #
  #   kill -9 <os_pid of workers-0-fn>
  #     → only workers-0-fn restarts (one_for_one)

  host do
    bridge "compute", subnet: {10, 0, 0, 0, 24}
  end

  # ── :linked — tightly coupled app + cache ─────────────

  pod "coupled", strategy: :one_for_all do
    container "app",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end

    container "cache",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["6379"],
      restart: :always do

      publish interval: 2000 do
        metric :memory
        metric :pids
      end
    end
  end

  # ── :ordered — pipeline with dependency chain ─────────

  pod "pipeline", strategy: :rest_for_one do
    container "ingest",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9001"],
      restart: :always do

      publish interval: 5000 do
        metric :memory
        metric :cpu
      end

      publish interval: 30_000 do
        metric :pressure
      end
    end

    container "transform",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9002"],
      restart: :always do

      publish interval: 5000 do
        metric :memory
        metric :cpu
      end
    end

    container "export",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9003"],
      restart: :always do

      publish interval: 5000 do
        metric :memory
        metric :cpu
      end
    end
  end

  # ── :one_for_one (default) — independent workers ───────

  pod "workers", strategy: :one_for_one do
    container "fn",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7000"],
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
    end
  end

  attach "coupled",  to: "compute", replicas: 1
  attach "pipeline", to: "compute", replicas: 1
  attach "workers",  to: "compute", replicas: 2
end
