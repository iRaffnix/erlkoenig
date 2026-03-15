defmodule ReverseProxyDemo do
  use Erlkoenig.DSL

  @moduledoc """
  Real-world demo: Go reverse proxy + Go echo server.

  Two containers — the proxy forwards HTTP traffic to the echo backend.
  Config is compiled into the args, no config files needed.

      ek-load /opt/erlkoenig/examples/caddy_proxy.exs
      curl http://localhost/hello
  """

  container :echo do
    binary "/opt/erlkoenig/rt/echo-server"
    ip {10, 0, 0, 20}
    args ["8080"]
    limits cpu: 1, memory: "64M", pids: 50
    restart :on_failure
    health_check port: 8080, interval: 5000, retries: 3
  end

  container :proxy do
    binary "/opt/erlkoenig/rt/reverse-proxy"
    ip {10, 0, 0, 10}
    args [":8080", "http://10.0.0.20:8080"]
    ports [{80, 8080}]
    limits cpu: 2, memory: "64M", pids: 50
    restart :on_failure
    health_check port: 8080, interval: 5000, retries: 3
  end
end
