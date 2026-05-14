defmodule LiveLabs.LifecycleMinimal do
  @moduledoc """
  Smallest live lifecycle lab.

  Expected journal signals:

    * `ek up` starts exactly one container: `life-0-echo`
    * lifecycle emits `container_started`
    * `ek down` emits `container_stopped`
    * no `container_oom`
    * no `firewall remove failed`
    * no `EK_CT_RESOURCE_ADMISSION_DENIED`

  Operator loop:

      journalctl -u erlkoenig -f
      /opt/erlkoenig/bin/ek up /tmp/ek_live_lab_01.term
      /opt/erlkoenig/bin/ek ct inspect life-0-echo
      /opt/erlkoenig/bin/ek down /tmp/ek_live_lab_01.term
  """
  use Erlkoenig.Stack

  host do
    ipvlan "life", parent: {:dummy, "ek_life"}, subnet: {10, 81, 0, 0, 24}
  end

  pod "life", strategy: :one_for_one do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      zone: "life",
      restart: :temporary,
      limits: %{memory: 96_000_000, pids: 64, cpu: 50}
  end
end
