defmodule WebCluster do
  use Erlkoenig.Stack

  pod "web_cluster" do
    container "web_api",
      binary: "/opt/bin/api_server",
      ports: [{8080, 80}, {8443, 443}],
      limits: %{memory: "512M", pids: 200},
      seccomp: :standard,
      restart: {:on_failure, 5},
      health_check: [port: 80, interval: 10_000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 80
        rule :accept, tcp: 443
        rule :drop, log: "DROP: "
      end
    end

    container "worker",
      binary: "/opt/bin/worker",
      args: ["--threads", "4"],
      limits: %{memory: "1G"},
      seccomp: :standard,
      restart: :on_failure do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, udp: 53
        rule :accept
      end
    end

    container "cache",
      binary: "/opt/bin/redis",
      limits: %{memory: "256M", pids: 50},
      seccomp: :strict,
      restart: :always,
      health_check: [port: 6379, interval: 5000, retries: 5] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 6379
        rule :drop, log: "DROP: "
      end
    end
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "web_cluster", replicas: 1
  end
end
