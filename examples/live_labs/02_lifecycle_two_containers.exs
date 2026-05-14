defmodule LiveLabs.LifecycleTwoContainers do
  @moduledoc """
  Two-container lifecycle lab.

  Expected journal signals:

    * `ek up` starts exactly two containers: `duo-0-echo` and `duo-0-worker`
    * each container emits `container_started`
    * `ek down` emits `container_stopped` for both containers
    * no `container_failed`
    * no `EK_CT_RESOURCE_ADMISSION_DENIED`

  Operator loop:

      /opt/erlkoenig/bin/ek dsl compile examples/live_labs/02_lifecycle_two_containers.exs -o /tmp/ek_live_lab_02.term
      journalctl -u erlkoenig -f
      /opt/erlkoenig/bin/ek up /tmp/ek_live_lab_02.term
      /opt/erlkoenig/bin/ek ct list
      /opt/erlkoenig/bin/ek down /tmp/ek_live_lab_02.term
  """
  use Erlkoenig.Stack

  host do
    ipvlan "duo", parent: {:dummy, "ek_duo"}, subnet: {10, 82, 0, 0, 24}
  end

  pod "duo", strategy: :one_for_one do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7781"],
      zone: "duo",
      restart: :temporary,
      limits: %{memory: 96_000_000, pids: 64, cpu: 50}

    container "worker",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7782"],
      zone: "duo",
      restart: :temporary,
      limits: %{memory: 96_000_000, pids: 64, cpu: 50}
  end
end
