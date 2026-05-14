defmodule LiveLabs.VolumesPersistent do
  @moduledoc """
  Persistent and hardened-volume lab.

  Expected operator signals:

    * `ek up` starts `vol-lab-0-svc`
    * `ek ct inspect vol-lab-0-svc` shows three resolved volumes
    * `ek vol list --container vol-lab-0-svc` shows:
      `primary-data`, `readonly-config`, and `upload-cache`
    * `ek vol inspect primary-data` returns the UUID-backed host path
    * `ek down` stops the container but persistent volume metadata remains

  Operator loop:

      /opt/erlkoenig/bin/ek dsl compile examples/live_labs/08_volumes_persistent.exs -o /tmp/ek_live_lab_08.term
      /opt/erlkoenig/bin/ek up /tmp/ek_live_lab_08.term
      /opt/erlkoenig/bin/ek ct inspect vol-lab-0-svc
      /opt/erlkoenig/bin/ek vol list --container vol-lab-0-svc
      /opt/erlkoenig/bin/ek vol inspect primary-data
      /opt/erlkoenig/bin/ek down /tmp/ek_live_lab_08.term
      /opt/erlkoenig/bin/ek vol list --container vol-lab-0-svc
  """
  use Erlkoenig.Stack

  host do
    ipvlan "vol", parent: {:dummy, "ek_vol_lab"}, subnet: {10, 88, 0, 0, 24}
  end

  pod "vol-lab", strategy: :one_for_one do
    container "svc",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      args: ["30"],
      zone: "vol",
      restart: :temporary,
      limits: %{memory: 96_000_000, pids: 64, cpu: 50} do

      volume "/data", persist: "primary-data"
      volume "/etc/app", persist: "readonly-config", read_only: true
      volume "/uploads",
             persist: "upload-cache",
             opts: "rw,nosuid,nodev,noexec,relatime"
    end
  end
end
