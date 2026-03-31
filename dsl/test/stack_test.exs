defmodule StackTest do
  use ExUnit.Case

  test "minimal stack with zone + container compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Minimal do
      use Erlkoenig.Stack

      images do
        image "myapp", path: "/tmp/myapp.erofs"
      end

      zone "apps", subnet: {10, 0, 0, 0}, gateway: {10, 0, 0, 1} do
        container "web",
          image: "myapp",
          binary: "/app",
          ip: {10, 0, 0, 10},
          restart: :always
      end
    end
    """)

    config = mod.config()

    assert config.images == %{"myapp" => "/tmp/myapp.erofs"}
    assert length(config.zones) == 1

    zone = hd(config.zones)
    assert zone.name == "apps"
    assert zone.subnet == {10, 0, 0, 0}
    assert length(zone.containers) == 1

    ct = hd(zone.containers)
    assert ct.name == "web"
    assert ct.binary == "/app"
    assert ct.image == "myapp"
    assert ct.image_path == "/tmp/myapp.erofs"
    assert ct.ip == {10, 0, 0, 10}
    assert ct.restart == :always
  end

  test "container with block (env, file, health_check)" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.WithBlock do
      use Erlkoenig.Stack

      images do
        image "api", path: "/tmp/api.erofs"
      end

      zone "apps" do
        container "api",
          image: "api",
          binary: "/app",
          ip: {10, 0, 0, 20} do

          env "DATABASE_URL", "postgres://10.0.0.1/db"
          env "PORT", "8080"
          file "/etc/config.yml", "key: value"
          health_check :tcp, port: 8080, interval: 3000
        end
      end
    end
    """)

    ct = mod.config().zones |> hd() |> Map.get(:containers) |> hd()
    assert ct.env == [{"DATABASE_URL", "postgres://10.0.0.1/db"}, {"PORT", "8080"}]
    assert ct.files == %{"/etc/config.yml" => "key: value"}
    assert ct.health_check == %{type: :tcp, port: 8080, interval: 3000, retries: 3}
  end

  test "steering with service and route" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Steering do
      use Erlkoenig.Stack

      images do
        image "web", path: "/tmp/web.erofs"
      end

      zone "apps" do
        container "web-1", image: "web", binary: "/app", ip: {10, 0, 0, 10}
        container "web-2", image: "web", binary: "/app", ip: {10, 0, 0, 11}
        container "worker", image: "web", binary: "/worker", ip: {10, 0, 0, 20}
      end

      steering do
        service :web_lb,
          vip: {10, 0, 0, 100},
          port: 80,
          proto: :tcp,
          backends: ["web-1", "web-2"]

        route "worker"
      end
    end
    """)

    steering = mod.config().steering
    assert length(steering.services) == 1
    svc = hd(steering.services)
    assert svc.name == :web_lb
    assert svc.vip == {10, 0, 0, 100}
    assert svc.backends == ["web-1", "web-2"]
    assert steering.routes == ["worker"]
  end

  test "guard auto-whitelists zone gateways" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Guard do
      use Erlkoenig.Stack

      zone "apps", gateway: {10, 0, 0, 1} do
        container "web", binary: "/app", ip: {10, 0, 0, 10}
      end

      guard do
        detect :conn_flood, threshold: 100, window: 10
        ban_duration 3600
        whitelist {127, 0, 0, 1}
      end
    end
    """)

    guard = mod.config().ct_guard
    assert {127, 0, 0, 1} in guard.whitelist
    assert {10, 0, 0, 1} in guard.whitelist
  end

  test "duplicate image name raises" do
    assert_raise CompileError, ~r/duplicate image/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.DupImage do
        use Erlkoenig.Stack
        images do
          image "app", path: "/a.erofs"
          image "app", path: "/b.erofs"
        end
      end
      """)
    end
  end

  test "undeclared image raises" do
    assert_raise CompileError, ~r/undeclared image/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadImage do
        use Erlkoenig.Stack
        images do
          image "real", path: "/a.erofs"
        end
        zone "apps" do
          container "web", image: "fake", binary: "/app", ip: {10, 0, 0, 10}
        end
      end
      """)
    end
  end

  test "unknown steering backend raises" do
    assert_raise CompileError, ~r/unknown backend/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadBackend do
        use Erlkoenig.Stack
        zone "apps" do
          container "web", binary: "/app", ip: {10, 0, 0, 10}
        end
        steering do
          service :lb, vip: {10, 0, 0, 100}, port: 80, proto: :tcp,
            backends: ["nonexistent"]
        end
      end
      """)
    end
  end

  test "duplicate container names across zones raises" do
    assert_raise CompileError, ~r/duplicate container/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.DupName do
        use Erlkoenig.Stack
        zone "a" do
          container "web", binary: "/app", ip: {10, 0, 0, 10}
        end
        zone "b", subnet: {10, 0, 1, 0}, gateway: {10, 0, 1, 1} do
          container "web", binary: "/app", ip: {10, 0, 1, 10}
        end
      end
      """)
    end
  end

  test "IP outside subnet raises" do
    assert_raise CompileError, ~r/outside zone subnet/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadIp do
        use Erlkoenig.Stack
        zone "apps", subnet: {10, 0, 0, 0} do
          container "web", binary: "/app", ip: {192, 168, 1, 10}
        end
      end
      """)
    end
  end

  test "empty stack produces minimal config" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Empty do
      use Erlkoenig.Stack
    end
    """)

    assert mod.config() == %{}
  end

  test "multiple containers in one zone" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Multi do
      use Erlkoenig.Stack

      images do
        image "app", path: "/tmp/app.erofs"
      end

      zone "apps" do
        container "web-1", image: "app", binary: "/app", ip: {10, 0, 0, 10}
        container "web-2", image: "app", binary: "/app", ip: {10, 0, 0, 11}
        container "web-3", image: "app", binary: "/app", ip: {10, 0, 0, 12}
      end
    end
    """)

    zone = hd(mod.config().zones)
    assert length(zone.containers) == 3
    names = Enum.map(zone.containers, & &1.name)
    assert names == ["web-1", "web-2", "web-3"]
  end
end
