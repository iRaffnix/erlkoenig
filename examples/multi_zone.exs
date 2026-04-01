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
  use Erlkoenig.Stack

  # Public-facing echo server in the frontend zone
  pod "web" do
    container "web",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      ports: [{8080, 8080}],
      restart: :on_failure do
    end
  end

  # Internal worker in the backend zone (no port mapping = not reachable from host)
  pod "worker" do
    container "worker",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9090"],
      restart: :on_failure do
    end
  end

  zone "frontend", subnet: {10, 0, 1, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "web", replicas: 1
  end

  zone "backend", subnet: {10, 0, 2, 0} do
    chain "forward", policy: :drop do
      rule :accept, ct: :established
      rule :drop
    end

    deploy "worker", replicas: 1
  end
end
