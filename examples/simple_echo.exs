defmodule SimpleEcho do
  use Erlkoenig.Stack

  # Minimal-Beispiel: ein einzelner Echo-Server auf einer Bridge.

  host do
    bridge "echo", subnet: {10, 0, 0, 0, 24}
  end

  pod "echo", strategy: :one_for_one do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      restart: :on_failure do

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

  attach "echo", to: "echo", replicas: 1
end
