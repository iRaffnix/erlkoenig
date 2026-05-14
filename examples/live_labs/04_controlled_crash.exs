defmodule LiveLabs.ControlledCrash do
  @moduledoc """
  Controlled container failure lab.

  Expected operator signals:

    * `ek up` creates `fail-0-crasher`
    * journalctl shows the start and then a stopped lifecycle signal with `term_signal => 11`
    * AMQP emits `container.fail-0-crasher.started` and `container.fail-0-crasher.stopped`
    * `ek ct inspect fail-0-crasher` shows `state failed` with `exit_info`
    * no resource-admission denial is involved

  Operator loop:

      /opt/erlkoenig/bin/ek dsl compile examples/live_labs/04_controlled_crash.exs -o /tmp/ek_live_lab_04.term
      journalctl -u erlkoenig -f
      /opt/erlkoenig/bin/ek up /tmp/ek_live_lab_04.term
      sleep 6
      /opt/erlkoenig/bin/ek ct inspect fail-0-crasher
  """
  use Erlkoenig.Stack

  host do
    ipvlan "fail", parent: {:dummy, "ek_fail"}, subnet: {10, 84, 0, 0, 24}
  end

  pod "fail", strategy: :one_for_one do
    container "crasher",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-crasher",
      args: [],
      zone: "fail",
      restart: :temporary,
      limits: %{memory: 96_000_000, pids: 64, cpu: 50}
  end
end
