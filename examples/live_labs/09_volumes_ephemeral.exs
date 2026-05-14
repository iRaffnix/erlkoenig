defmodule LiveLabs.VolumesEphemeral do
  @moduledoc """
  Ephemeral-volume cleanup lab.

  Expected operator signals:

    * `ek up` starts `eph-lab-0-worker`
    * `ek vol list --container eph-lab-0-worker` shows `scratch-run`
    * `ek down` stops the container
    * after stop, `ek vol list --container eph-lab-0-worker` is empty
    * `ek vol orphans` is empty

  Operator loop:

      /opt/erlkoenig/bin/ek dsl compile examples/live_labs/09_volumes_ephemeral.exs -o /tmp/ek_live_lab_09.term
      /opt/erlkoenig/bin/ek up /tmp/ek_live_lab_09.term
      /opt/erlkoenig/bin/ek vol list --container eph-lab-0-worker
      /opt/erlkoenig/bin/ek down /tmp/ek_live_lab_09.term
      /opt/erlkoenig/bin/ek vol list --container eph-lab-0-worker
      /opt/erlkoenig/bin/ek vol orphans
  """
  use Erlkoenig.Stack

  host do
    ipvlan "eph", parent: {:dummy, "ek_eph_lab"}, subnet: {10, 89, 0, 0, 24}
  end

  pod "eph-lab", strategy: :one_for_one do
    container "worker",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      args: ["30"],
      zone: "eph",
      restart: :temporary,
      limits: %{memory: 96_000_000, pids: 64, cpu: 50} do

      volume "/scratch",
             persist: "scratch-run",
             opts: "rw,nosuid,nodev,noexec",
             ephemeral: true
    end
  end
end
