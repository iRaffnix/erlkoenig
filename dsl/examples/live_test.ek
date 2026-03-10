defmodule LiveTest do
  use Erlkoenig.DSL

  container :echo_a do
    binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
    ip {10, 0, 0, 10}
    args ["7777"]
    restart :on_failure
    health_check port: 7777, interval: 5000, retries: 3
    firewall :standard
  end

  container :echo_b do
    binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
    ip {10, 0, 0, 20}
    args ["8888"]
    ports [{9080, 8888}]
    restart {:on_failure, 3}
    health_check port: 8888, interval: 5000, retries: 3
    firewall :strict, allow_tcp: [8888]
  end
end
