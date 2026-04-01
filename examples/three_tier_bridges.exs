defmodule ThreeTier do
  use Erlkoenig.Stack

  host do
    interface "eth0", zone: :wan

    bridge "dmz",  subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
    bridge "app",  subnet: {10, 0, 1, 0, 24}
    bridge "data", subnet: {10, 0, 2, 0, 24}

    chain "input", hook: :input, policy: :drop do
      rule :accept, ct: :established
      rule :accept, iif: "lo"
      rule :accept, tcp: 22
      rule :drop, log: "HOST: "
    end

    chain "forward", hook: :forward, policy: :drop do
      rule :accept, ct: :established

      # WAN → DMZ: nur Port 8443
      rule :accept, iif: "eth0", oif: "web.nginx", tcp: 8443

      # DMZ → App: nginx → api
      rule :accept, iif: "web.nginx", oif: "app.api", tcp: 4000

      # App → Data: api → postgres
      rule :accept, iif: "app.api", oif: "data.postgres", tcp: 5432

      # Container → Internet
      rule :accept, iif: "dmz", oif: "eth0"

      rule :drop, log: "FWD: "
    end

    chain "postrouting", hook: :postrouting, type: :nat do
      rule :masquerade, iif: "dmz", oif: "eth0"
    end
  end

  pod "web" do
    container "nginx",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8443"] do
      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 8443
        rule :drop
      end
    end
  end

  pod "app" do
    container "api",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["4000"] do
      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 4000
        rule :drop
      end
    end
  end

  pod "data" do
    container "postgres",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["5432"] do
      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 5432
        rule :drop
      end
    end
  end

  attach "web",  to: "dmz",  replicas: 1
  attach "app",  to: "app",  replicas: 1
  attach "data", to: "data", replicas: 1
end
