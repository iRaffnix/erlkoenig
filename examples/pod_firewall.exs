defmodule PodFirewall do
  use Erlkoenig.Stack

  # ═══════════════════════════════════════════════════
  # Host — was darf auf den Host selbst
  # ═══════════════════════════════════════════════════

  firewall "host" do
    counters [:ssh, :dropped]

    chain "input", hook: :input, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "lo"
      rule :accept, tcp: 22, limit: {25, burst: 5}, counter: :ssh
      rule :drop, log: "HOST_DROP: ", counter: :dropped
    end
  end

  # ═══════════════════════════════════════════════════
  # Pod — Container-Gruppe mit interner Firewall
  # ═══════════════════════════════════════════════════

  pod "web" do
    container "frontend",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"] do
      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 8080
        rule :drop
      end
    end

    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"] do
      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 4000
        rule :drop
      end
    end

    # Was darf zwischen Containern im Pod
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: {:ref, "frontend"}, oif: {:ref, "api"}, tcp: 4000
      rule :drop, log: "POD_DROP: "
    end
  end

  # ═══════════════════════════════════════════════════
  # Zone — was darf zwischen Host und Containern
  # ═══════════════════════════════════════════════════

  zone "test", subnet: {10, 0, 0, 0} do
    # :bridge = Zone-Bridge, :containers = alle Container-veths
    chain "forward" do
      rule :accept, iif: :bridge, oif: :containers
    end

    deploy "web", replicas: 1
  end
end
