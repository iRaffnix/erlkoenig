#
# Example: Container with FUSE rootfs definition
#
# Demonstrates the rootfs block for building a content-addressed
# filesystem that gets FUSE-mounted into the container.
#

defmodule FuseRootfsExample do
  use Erlkoenig.Stack

  # TODO: migrate fuse_rootfs when supported

  pod "web" do
    container "web",
      binary: "/opt/erlkoenig/rt/demo/web",
      limits: %{memory: "256M", pids: 50},
      seccomp: :standard,
      restart: :on_failure do

      chain "inbound", policy: :drop do
        rule :accept, ct: :established
        rule :accept, tcp: 8080
        rule :drop, log: "TRAP: "
      end
    end
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "web", replicas: 1
  end
end
