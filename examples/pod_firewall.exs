defmodule PodFirewall do
  use Erlkoenig.Stack

  # ── Host Firewall ─────────────────────────────────
  firewall "host" do
    counters [:ssh, :dropped]

    chain "input", hook: :input, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "lo"
      rule :accept, tcp: 22, limit: {25, burst: 5}, counter: :ssh
      rule :drop, log: "HOST_DROP: ", counter: :dropped
    end
  end

  # ── Pod: 2 Container mit interner Firewall ────────
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

    # Inter-Container: nur frontend → api:4000, sonst drop
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: {:ref, "frontend"}, oif: {:ref, "api"}, tcp: 4000
      rule :drop, log: "POD_DROP: "
    end
  end

  # ── Zone: Deployment + Netzwerk zum Host ──────────
  zone "test", subnet: {10, 0, 0, 0} do
    chain "forward" do
      rule :accept, iif: "ek_br_test", oif: "vh_*"
    end
    deploy "web", replicas: 1
  end
end
