defmodule ReverseProxyDemo do
  use Erlkoenig.Stack

  @moduledoc """
  Real-world demo: Go reverse proxy + Go echo server.

  Two containers — the proxy forwards HTTP traffic to the echo backend.
  Config is compiled into the args, no config files needed.

      ek-load /opt/erlkoenig/examples/caddy_proxy.exs
      curl http://localhost/hello
  """

  pod "reverse_proxy" do
    container "echo",
      binary: "/opt/erlkoenig/rt/echo-server",
      args: ["8080"],
      limits: %{memory: "64M", pids: 50},
      restart: :on_failure,
      health_check: [port: 8080, interval: 5000, retries: 3] do
    end

    container "proxy",
      binary: "/opt/erlkoenig/rt/reverse-proxy",
      args: [":8080", "http://10.0.0.20:8080"],
      ports: [{80, 8080}],
      limits: %{memory: "64M", pids: 50},
      restart: :on_failure,
      health_check: [port: 8080, interval: 5000, retries: 3] do
    end
  end

  zone "default", subnet: {10, 0, 0, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "reverse_proxy", replicas: 1
  end
end
