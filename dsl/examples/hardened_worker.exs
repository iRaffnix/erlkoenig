defmodule HardenedWorker do
  use Erlkoenig.DSL

  container :worker do
    binary "/opt/bin/compute_worker"
    ip {10, 0, 0, 50}
    args ["--queue", "default"]
    env %{"RUST_LOG" => "info"}
    limits cpu: 2, memory: "512M", pids: 100, pps: 5000
    seccomp :strict
    restart {:on_failure, 10}
    health_check port: 9090, interval: 15_000, retries: 5

    firewall do
      accept :established
      accept :icmp
      accept_udp 53
      log_and_drop "DROP: "
    end
  end
end
