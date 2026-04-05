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
  use Erlkoenig.Stack

  # TODO: migrate volume mounts when supported

  pod "archive" do
    container "archive",
      binary: "/opt/bin/archive_server",
      args: ["--data-dir", "/data/db", "--log-dir", "/var/log/app"],
      limits: %{memory: "1G", pids: 200},
      seccomp: :standard,
      restart: {:on_failure, 5},
      health_check: [port: 9090, interval: 10_000, retries: 3] do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :accept, tcp: 8080
        rule :accept, tcp: 9090
        rule :drop, log: "archive-drop: "
      end
    end

    container "indexer",
      binary: "/opt/bin/indexer",
      args: ["--archive-host", "10.0.0.30", "--index-dir", "/data/index"],
      limits: %{memory: "512M", pids: 50},
      seccomp: :standard,
      restart: {:on_failure, 3} do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, icmp: true
        rule :drop, log: "indexer-drop: "
      end
    end
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "archive", replicas: 1
  end
end
