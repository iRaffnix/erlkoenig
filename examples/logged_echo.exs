defmodule LoggedEcho do
  use Erlkoenig.Stack

  # ── Log Streaming Demo ───────────────────────────────────
  #
  # Container mit stdout/stderr Streaming nach RabbitMQ.
  #
  # Starten:
  #   erlkoenig eval 'erlkoenig_config:load(<<"/tmp/logged_echo.term">>).'
  #
  # Stream Consumer:
  #   python3 tools/stream_consumer.py erlkoenig.log.echo-0-echo
  #   python3 tools/stream_consumer.py erlkoenig.log.echo-0-echo --filter stderr

  host do
    bridge "net", subnet: {10, 0, 0, 0, 24}
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

      stream retention: {7, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end

  attach "echo", to: "net", replicas: 1
end
