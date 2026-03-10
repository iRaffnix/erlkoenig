defmodule WebCluster do
  use Erlkoenig.DSL

  defaults do
    firewall :standard
  end

  container :web_api do
    binary "/opt/bin/api_server"
    ip {10, 0, 0, 10}
    ports [{8080, 80}, {8443, 443}]
    env %{"PORT" => "80", "ENV" => "prod"}
    limits cpu: 2, memory: "512M", pids: 200
    seccomp :standard
    restart {:on_failure, 5}
    health_check port: 80, interval: 10_000, retries: 3
    firewall :strict, allow_tcp: [80, 443]
  end

  container :worker do
    binary "/opt/bin/worker"
    ip {10, 0, 0, 20}
    args ["--threads", "4"]
    limits cpu: 4, memory: "1G"
    seccomp :standard
    restart :on_failure
  end

  container :cache do
    binary "/opt/bin/redis"
    ip {10, 0, 0, 30}
    limits cpu: 1, memory: "256M", pids: 50
    seccomp :strict
    restart :always
    health_check port: 6379, interval: 5000, retries: 5
    firewall :strict, allow_tcp: [6379]
  end

  watch :traffic do
    counter :http_pkts, :pps, threshold: 10_000
    counter :dropped, :packets, threshold: 500
    interval 3000
    on_alert :log
    on_alert {:webhook, "https://alerts.internal/erlkoenig"}
  end

  guard do
    detect :conn_flood, threshold: 100, window: 10
    detect :port_scan, threshold: 20, window: 60
    ban_duration 1800
  end
end
