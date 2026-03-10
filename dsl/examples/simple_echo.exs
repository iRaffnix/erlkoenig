defmodule SimpleEcho do
  use Erlkoenig.DSL

  container :echo do
    binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
    ip {10, 0, 0, 5}
    args ["7777"]
    ports [{9080, 7777}]
    restart :on_failure
    health_check port: 7777, interval: 5000, retries: 3
  end
end
