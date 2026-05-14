defmodule LiveLabs.ObservabilityStats do
  @moduledoc """
  Container lifecycle plus cgroup stats lab.

  Expected operator signals:

    * `ek up` starts `obs-0-echo`
    * journalctl shows container start/stop lifecycle lines
    * `ek ct inspect obs-0-echo` includes live cgroup stats
    * AMQP emits stats for memory, cpu, pids, pressure and oom
    * `ek down` stops the container cleanly

  Operator loop:

      /opt/erlkoenig/bin/ek dsl compile examples/live_labs/03_observability_stats.exs -o /tmp/ek_live_lab_03.term
      journalctl -u erlkoenig -f
      /opt/erlkoenig/bin/ek up /tmp/ek_live_lab_03.term
      sleep 4
      /opt/erlkoenig/bin/ek ct inspect obs-0-echo
      /opt/erlkoenig/bin/ek down /tmp/ek_live_lab_03.term
  """
  use Erlkoenig.Stack

  host do
    ipvlan "obs", parent: {:dummy, "ek_obs"}, subnet: {10, 83, 0, 0, 24}
  end

  pod "obs", strategy: :one_for_one do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7783"],
      zone: "obs",
      restart: :temporary,
      limits: %{memory: 128_000_000, pids: 96, cpu: 50} do

      publish interval: 1000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      publish interval: 2000 do
        metric :pressure
        metric :oom_events
      end
    end
  end
end
