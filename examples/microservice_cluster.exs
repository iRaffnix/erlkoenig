defmodule MicroserviceCluster do
  use Erlkoenig.Stack

  # --- DMZ Zone: Internet-facing ---

  pod "gateway" do
    container "gateway",
      binary: "/opt/bin/gateway",
      ports: [{80, 8080}, {443, 8443}],
      limits: %{memory: "256M"},
      seccomp: :standard,
      restart: :always,
      health_check: [port: 8080, interval: 5000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 8080
        rule :accept, tcp: 8443
        rule :drop, log: "DROP: "
      end
    end
  end

  # --- Internal services ---

  pod "services" do
    container "auth_service",
      binary: "/opt/bin/auth",
      limits: %{memory: "128M", pids: 50},
      seccomp: :standard,
      restart: {:on_failure, 5},
      health_check: [port: 3000, interval: 10_000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 3000
        rule :drop, log: "DROP: "
      end
    end

    container "api_service",
      binary: "/opt/bin/api",
      limits: %{memory: "1G", pids: 200},
      seccomp: :standard,
      restart: {:on_failure, 5},
      health_check: [port: 4000, interval: 10_000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 4000
        rule :drop, log: "DROP: "
      end
    end

    container "database",
      binary: "/opt/bin/sqlite_server",
      limits: %{memory: "2G", pids: 100},
      seccomp: :strict,
      restart: :always,
      health_check: [port: 5432, interval: 5000, retries: 5] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 5432
        rule :drop, log: "DROP: "
      end
    end
  end

  zone "dmz", subnet: {10, 0, 1, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "gateway", replicas: 1
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "services", replicas: 1
  end
end
