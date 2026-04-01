defmodule HardenedWorker do
  use Erlkoenig.Stack

  pod "worker" do
    container "worker",
      binary: "/opt/bin/compute_worker",
      args: ["--queue", "default"],
      limits: %{memory: "512M", pids: 100},
      seccomp: :strict,
      restart: {:on_failure, 10},
      health_check: [port: 9090, interval: 15_000, retries: 5] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, udp: 53
        rule :drop, log: "DROP: "
      end
    end
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "worker", replicas: 1
  end
end
