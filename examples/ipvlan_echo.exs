defmodule IpvlanEcho do
  use Erlkoenig.Stack

  # ══════════════════════════════════════════════════════════
  # IPVLAN Example — Container mit IPVLAN L3S statt Bridge
  # ══════════════════════════════════════════════════════════
  #
  # Zeigt: IPVLAN statt Bridge, keine MAC-Promiscuity noetig,
  # Cloud-VPS kompatibel (Hetzner, AWS, etc.).
  #
  # Unterschied zu simple_echo.exs:
  #   bridge "echo", subnet: ...
  #   →
  #   ipvlan "edge", parent: "eth0", subnet: ...
  #
  # Der Rest ist identisch: Pod, Container, attach.
  #
  # Der Parent ("eth0") muss ein bestehendes Host-Interface sein.
  # erlkoenig verwaltet es nicht — es muss vom Operator konfiguriert
  # und UP sein. IPVLAN-Slaves werden daran angehängt.
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
      restart: :on_failure
  end

  attach "echo", to: "edge", replicas: 1
end
