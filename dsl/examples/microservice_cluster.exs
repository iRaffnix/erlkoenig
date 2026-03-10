defmodule MicroserviceCluster do
  use Erlkoenig.DSL

  defaults do
    firewall :standard
  end

  # --- DMZ Zone: Internet-facing ---

  container :gateway do
    binary "/opt/bin/gateway"
    ip {10, 0, 1, 10}
    zone :dmz
    ports [{80, 8080}, {443, 8443}]
    limits cpu: 2, memory: "256M"
    seccomp :standard
    restart :always
    health_check port: 8080, interval: 5000, retries: 3
    firewall :strict, allow_tcp: [8080, 8443]
  end

  # --- Default Zone: Internal services ---

  container :auth_service do
    binary "/opt/bin/auth"
    ip {10, 0, 0, 11}
    limits cpu: 1, memory: "128M", pids: 50
    seccomp :standard
    restart {:on_failure, 5}
    health_check port: 3000, interval: 10_000, retries: 3
    firewall :strict, allow_tcp: [3000]
  end

  container :api_service do
    binary "/opt/bin/api"
    ip {10, 0, 0, 12}
    limits cpu: 4, memory: "1G", pids: 200
    seccomp :standard
    restart {:on_failure, 5}
    health_check port: 4000, interval: 10_000, retries: 3
    firewall :strict, allow_tcp: [4000]
  end

  container :database do
    binary "/opt/bin/sqlite_server"
    ip {10, 0, 0, 20}
    limits cpu: 2, memory: "2G", pids: 100
    seccomp :strict
    restart :always
    health_check port: 5432, interval: 5000, retries: 5
    firewall :strict, allow_tcp: [5432]
  end

  watch :cluster_health do
    counter :gateway_pkts, :pps, threshold: 50_000
    counter :auth_pkts, :pps, threshold: 10_000
    counter :dropped, :packets, threshold: 500
    interval 5000
    on_alert :log
    on_alert {:webhook, "https://monitoring.internal/alerts"}
  end

  guard do
    detect :conn_flood, threshold: 200, window: 10
    detect :port_scan, threshold: 15, window: 30
    ban_duration 3600
    whitelist {10, 0, 0, 1}
  end
end
