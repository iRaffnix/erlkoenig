#
# Example: Persistent Archive Stack with Volumes
#
# This example demonstrates the use of bind-mount volumes for
# persistent storage across container restarts. The archive
# container stores database files, logs, and reads shared
# configuration from a read-only volume.
#
# Host paths are resolved automatically:
#   /var/lib/erlkoenig/volumes/<container>/<persist>/
#

defmodule PersistentArchive do
  use Erlkoenig.Container

  defaults do
    firewall :standard
  end

  container :archive do
    binary "/opt/bin/archive_server"
    ip {10, 0, 0, 30}
    args ["--data-dir", "/data/db", "--log-dir", "/var/log/app"]
    env %{"RUST_LOG" => "info", "ARCHIVE_MODE" => "persistent"}
    restart {:on_failure, 5}

    # Persistent volumes — survive container restarts
    volume "/data/db", persist: "archive-db"
    volume "/var/log/app", persist: "archive-logs"
    volume "/etc/config", persist: "shared-config", read_only: true

    limits memory: "1G", cpu: 2, pids: 200
    seccomp :default

    firewall do
      accept :established
      accept :icmp
      accept_tcp 8080
      accept_tcp 9090
      log_and_drop "archive-drop: "
    end

    health_check port: 9090, interval: 10_000, retries: 3
  end

  container :indexer do
    binary "/opt/bin/indexer"
    ip {10, 0, 0, 31}
    args ["--archive-host", "10.0.0.30", "--index-dir", "/data/index"]
    env %{"RUST_LOG" => "warn"}
    restart {:on_failure, 3}

    # Indexer has its own persistent index directory
    volume "/data/index", persist: "index-data"

    limits memory: "512M", cpu: 1, pids: 50
    seccomp :default

    firewall do
      accept :established
      accept :icmp
      log_and_drop "indexer-drop: "
    end
  end
end
