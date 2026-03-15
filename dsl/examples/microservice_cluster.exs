defmodule MicroserviceCluster do
  use Erlkoenig.DSL

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

    firewall do
      accept :established
      accept :icmp
      accept_tcp 8080
      accept_tcp 8443
      log_and_drop "DROP: "
    end
  end

  # --- Default Zone: Internal services ---

  container :auth_service do
    binary "/opt/bin/auth"
    ip {10, 0, 0, 11}
    limits cpu: 1, memory: "128M", pids: 50
    seccomp :standard
    restart {:on_failure, 5}
    health_check port: 3000, interval: 10_000, retries: 3

    firewall do
      accept :established
      accept :icmp
      accept_tcp 3000
      log_and_drop "DROP: "
    end
  end

  container :api_service do
    binary "/opt/bin/api"
    ip {10, 0, 0, 12}
    limits cpu: 4, memory: "1G", pids: 200
    seccomp :standard
    restart {:on_failure, 5}
    health_check port: 4000, interval: 10_000, retries: 3

    firewall do
      accept :established
      accept :icmp
      accept_tcp 4000
      log_and_drop "DROP: "
    end
  end

  container :database do
    binary "/opt/bin/sqlite_server"
    ip {10, 0, 0, 20}
    limits cpu: 2, memory: "2G", pids: 100
    seccomp :strict
    restart :always
    health_check port: 5432, interval: 5000, retries: 5

    firewall do
      accept :established
      accept :icmp
      accept_tcp 5432
      log_and_drop "DROP: "
    end
  end

end
