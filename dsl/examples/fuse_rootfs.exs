#
# Example: Container with FUSE rootfs definition
#
# Demonstrates the rootfs block for building a content-addressed
# filesystem that gets FUSE-mounted into the container.
#

defmodule FuseRootfsExample do
  use Erlkoenig.DSL

  container :web do
    binary "/opt/erlkoenig/rt/demo/web"
    ip {10, 0, 0, 10}
    zone :default
    restart :on_failure
    limits memory: "256M", cpu: 2, pids: 50
    seccomp :standard

    rootfs do
      base :minimal
      file "/etc/ssl/certs/ca-certificates.crt", from: :host
      file "/etc/myapp/config.json", content: ~S'{"port": 8080, "env": "production"}'
      directory "/etc/myapp/templates", from: "configs/templates/"
      tmpfs "/tmp", size: "64M"
      tmpfs "/run", size: "16M"
    end

    firewall do
      accept :established
      accept_tcp 8080, counter: :http
      log_and_drop "TRAP: ", counter: :trap
    end
  end
end
