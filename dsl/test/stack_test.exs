defmodule StackTest do
  use ExUnit.Case

  test "empty stack produces minimal config" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Empty do
      use Erlkoenig.Stack
    end
    """)

    assert mod.config() == %{}
  end

  test "host with interface and bridge" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.HostOnly do
      use Erlkoenig.Stack

      host do
        interface "eth0", zone: :wan
        bridge "br0", subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
      end
    end
    """)

    config = mod.config()
    assert config.host.bridges == [%{name: "br0", subnet: {10, 0, 0, 0},
      netmask: 24, gateway: {10, 0, 0, 1}, uplink: "eth0"}]
  end

  test "pod + attach compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.HostAttach do
      use Erlkoenig.Stack

      host do
        interface "eth0", zone: :wan
        bridge "br0", subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
      end

      pod "web" do
        container "frontend", binary: "/opt/frontend"
        container "api", binary: "/opt/api"
      end

      attach "web", to: "br0", replicas: 3
    end
    """)

    config = mod.config()
    assert length(config.zones) == 1
    zone = hd(config.zones)
    assert zone.name == "br0"
    assert zone.deployments == [%{pod: "web", replicas: 3}]
  end

  test "multi-bridge three-tier" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.ThreeTier do
      use Erlkoenig.Stack

      host do
        interface "eth0", zone: :wan
        bridge "dmz",  subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
        bridge "app",  subnet: {10, 0, 1, 0, 24}
        bridge "data", subnet: {10, 0, 2, 0, 24}
      end

      pod "web" do
        container "nginx", binary: "/opt/nginx"
      end

      pod "app" do
        container "api", binary: "/opt/api"
      end

      pod "data" do
        container "postgres", binary: "/opt/pg"
      end

      attach "web",  to: "dmz",  replicas: 3
      attach "app",  to: "app",  replicas: 2
      attach "data", to: "data", replicas: 1
    end
    """)

    config = mod.config()
    assert length(config.zones) == 3
    names = Enum.map(config.zones, & &1.name)
    assert "dmz" in names
    assert "app" in names
    assert "data" in names

    dmz = Enum.find(config.zones, & &1.name == "dmz")
    assert dmz.subnet == {10, 0, 0, 0}
    assert dmz.deployments == [%{pod: "web", replicas: 3}]
  end

  test "guard compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.GuardNew do
      use Erlkoenig.Stack

      guard do
        detect :conn_flood, threshold: 50, window: 10
        detect :port_scan, threshold: 20, window: 60
        ban_duration 3600
        whitelist {127, 0, 0, 1}
      end
    end
    """)

    guard = mod.config().ct_guard
    assert guard.conn_flood == {50, 10}
    assert guard.ban_duration == 3600
    assert {127, 0, 0, 1} in guard.whitelist
  end

  test "same pod attached to multiple bridges" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.MultiAttach do
      use Erlkoenig.Stack

      host do
        bridge "region_eu", subnet: {10, 1, 0, 0, 24}
        bridge "region_us", subnet: {10, 2, 0, 0, 24}
      end

      pod "worker" do
        container "fn", binary: "/opt/fn"
      end

      attach "worker", to: "region_eu", replicas: 3
      attach "worker", to: "region_us", replicas: 2
    end
    """)

    config = mod.config()
    eu = Enum.find(config.zones, & &1.name == "region_eu")
    us = Enum.find(config.zones, & &1.name == "region_us")

    assert eu.deployments == [%{pod: "worker", replicas: 3}]
    assert us.deployments == [%{pod: "worker", replicas: 2}]
  end

  test "attach references unknown pod raises" do
    assert_raise CompileError, ~r/unknown pod/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadAttach do
        use Erlkoenig.Stack
        host do
          bridge "br0", subnet: {10, 0, 0, 0, 24}
        end
        attach "nonexistent", to: "br0", replicas: 1
      end
      """)
    end
  end

  test "attach references unknown bridge raises" do
    assert_raise CompileError, ~r/unknown bridge/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadBridge do
        use Erlkoenig.Stack
        pod "web" do
          container "app", binary: "/opt/app"
        end
        host do
          bridge "br0", subnet: {10, 0, 0, 0, 24}
        end
        attach "web", to: "missing", replicas: 1
      end
      """)
    end
  end

  test "pod with duplicate container names raises" do
    assert_raise CompileError, ~r/duplicate container/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.DupCt do
        use Erlkoenig.Stack
        pod "bad" do
          container "web", binary: "/a"
          container "web", binary: "/b"
        end
      end
      """)
    end
  end

  test "pod without containers raises" do
    assert_raise CompileError, ~r/at least one container/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.EmptyPod do
        use Erlkoenig.Stack
        pod "empty" do
        end
      end
      """)
    end
  end

  test "pod strategy: defaults to one_for_one" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.DefaultStrategy do
      use Erlkoenig.Stack
      pod "web" do
        container "app", binary: "/opt/app"
      end
    end
    """)

    pod = hd(mod.config().pods)
    assert pod.strategy == :one_for_one
  end

  test "pod strategy: :one_for_all" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.LinkedPod do
      use Erlkoenig.Stack
      pod "backend", strategy: :one_for_all do
        container "db", binary: "/opt/db"
        container "api", binary: "/opt/api"
      end
    end
    """)

    pod = hd(mod.config().pods)
    assert pod.name == "backend"
    assert pod.strategy == :one_for_all
    assert length(pod.containers) == 2
  end

  test "pod strategy: :rest_for_one preserves container order" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.OrderedPod do
      use Erlkoenig.Stack
      pod "pipeline", strategy: :rest_for_one do
        container "db", binary: "/opt/db"
        container "api", binary: "/opt/api"
        container "proxy", binary: "/opt/proxy"
      end
    end
    """)

    pod = hd(mod.config().pods)
    assert pod.strategy == :rest_for_one
    names = Enum.map(pod.containers, & &1.name)
    assert names == ["db", "api", "proxy"]
  end

  test "pod strategy: invalid value raises" do
    assert_raise CompileError, ~r/invalid strategy.*:banana/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadStrategy do
        use Erlkoenig.Stack
        pod "bad", strategy: :banana do
          container "x", binary: "/opt/x"
        end
      end
      """)
    end
  end

  test "mixed strategies in one stack" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.MixedStrategies do
      use Erlkoenig.Stack

      host do
        bridge "br0", subnet: {10, 0, 0, 0, 24}
      end

      pod "db", strategy: :one_for_all do
        container "primary", binary: "/opt/pg"
        container "replica", binary: "/opt/pg"
      end

      pod "workers" do
        container "fn", binary: "/opt/fn"
      end

      pod "pipeline", strategy: :rest_for_one do
        container "ingest", binary: "/opt/ingest"
        container "process", binary: "/opt/proc"
        container "export", binary: "/opt/export"
      end

      attach "db", to: "br0", replicas: 1
      attach "workers", to: "br0", replicas: 5
      attach "pipeline", to: "br0", replicas: 1
    end
    """)

    config = mod.config()
    strategies = Map.new(config.pods, &{&1.name, &1.strategy})
    assert strategies["db"] == :one_for_all
    assert strategies["workers"] == :one_for_one
    assert strategies["pipeline"] == :rest_for_one
  end

  test "pod container without binary raises" do
    assert_raise CompileError, ~r/missing binary/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.NoBin do
        use Erlkoenig.Stack
        pod "bad" do
          container "web", image: "foo"
        end
      end
      """)
    end
  end
end
