defmodule MultiZone do
  @moduledoc """
  Multi-zone networking example.

  Demonstrates network isolation: a "frontend" zone for public-facing
  services and a "backend" zone for internal workers.

  Before loading, create the zones:

      ek-net create frontend 10.0.1.0/24
      ek-net create backend  10.0.2.0/24
      ek-load multi_zone.exs

  Or use the default zone for everything:

      ek-load simple_echo.exs
  """
  use Erlkoenig.DSL

  # Public-facing echo server in the frontend zone
  container :web do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"
    zone :frontend
    ip {10, 0, 1, 10}
    args ["8080"]
    ports [{8080, 8080}]
    restart :on_failure
  end

  # Internal worker in the backend zone (no port mapping = not reachable from host)
  container :worker do
    binary "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"
    zone :backend
    ip {10, 0, 2, 10}
    args ["9090"]
    restart :on_failure
  end
end
