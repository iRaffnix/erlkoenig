defmodule LiveLabs.LogStream do
  @moduledoc """
  Container stdout/stderr log-streaming lab.

  Expected operator signals:

    * `ek up` starts `log-0-speaker`
    * journalctl shows lifecycle start/stop
    * RabbitMQ stream `erlkoenig.log.log-0-speaker` receives stdout/stderr chunks
    * `ek ct inspect log-0-speaker` ends in a terminal state after the demo binary exits

  Operator loop:

      /opt/erlkoenig/bin/ek dsl compile examples/live_labs/07_log_stream.exs -o /tmp/ek_live_lab_07.term
      python3 tools/stream_consumer.py erlkoenig.log.log-0-speaker --offset next
      /opt/erlkoenig/bin/ek up /tmp/ek_live_lab_07.term
      sleep 3
      /opt/erlkoenig/bin/ek ct inspect log-0-speaker
  """
  use Erlkoenig.Stack

  host do
    ipvlan "log", parent: {:dummy, "ek_log"}, subnet: {10, 87, 0, 0, 24}
  end

  pod "log", strategy: :one_for_one do
    container "speaker",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-hello_output",
      args: [],
      zone: "log",
      restart: :temporary,
      limits: %{memory: 96_000_000, pids: 64, cpu: 50} do

      stream retention: {1, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end
end
