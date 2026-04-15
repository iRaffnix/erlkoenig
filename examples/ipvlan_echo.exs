defmodule IpvlanEcho do
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════
  # IPVLAN Example — Slave auf physischem Host-Interface
  # ══════════════════════════════════════════════════════════
  #
  # Zeigt: IPVLAN L3S auf {:device, "eth0"} — keine MAC-Promiscuity,
  # Cloud-VPS kompatibel (Hetzner, AWS, etc.). Unterschied zu simple_echo:
  # dort ist Parent ein {:dummy, ...} (keine externe Konnektivität).
  #
  # Der Parent muss ein bestehendes Host-Interface sein und UP.
  # erlkoenig verwaltet es nicht — es muss vom Operator konfiguriert
  # sein. IPVLAN-Slaves werden daran angehängt.
  #
  # Starten:
  #   mix run -e '
  #     [{mod, _}] = Code.compile_file("examples/ipvlan_echo.exs")
  #     mod.write!("/tmp/ipvlan_echo.term")
  #   '

  host do
    interface "eth0"
    ipvlan "edge",
      parent: {:device, "eth0"},
      subnet: {10, 20, 0, 0, 24}
      # mode: :l3s is the default — per-slave conntrack/netfilter
      # gateway: optional — IPVLAN L3S uses device routing by default
  end

  pod "echo", strategy: :one_for_one do
    container "echo",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["7777"],
      zone: "edge", replicas: 1, restart: :transient
  end
end
