defmodule PodFirewall do
  use Erlkoenig.Stack

  # ── Host ──────────────────────────────

  host do
    interface "eth0", zone: :wan
    interface "eth1", zone: :lan
    bridge "br0", subnet: {10, 0, 0, 0, 24}, uplink: "eth0"

    chain "input", hook: :input, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "lo"
      rule :accept, iif: "eth1"
      rule :accept, iif: "eth0", tcp: 22, limit: {25, burst: 5}
      rule :drop, log: "HOST_DROP: "
    end

    chain "forward", hook: :forward, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "eth0", oif: "web.frontend", tcp: 8080
      rule :accept, iif: "eth1", oif: "web.api", tcp: 4000
      rule :accept, iif: "web.frontend", oif: "web.api", tcp: 4000
      rule :accept, iif: "br0", oif: "eth0"
      rule :drop, log: "FWD_DROP: "
    end

    chain "postrouting", hook: :postrouting, type: :nat do
      rule :masquerade, iif: "br0", oif: "eth0"
    end
  end

  # ── Pods ──────────────────────────────

  pod "web" do
    container "frontend",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      limits: %{memory: 256_000_000, pids: 100},
      restart: :on_failure do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 8080
        rule :drop
      end
    end

    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"],
      limits: %{memory: 512_000_000, pids: 200},
      restart: :on_failure do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 4000
        rule :drop
      end
    end
  end

  attach "web", to: "br0", replicas: 1
end
