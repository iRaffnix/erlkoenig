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

  test "host with interface and ipvlan" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.HostOnly do
      use Erlkoenig.Stack

      host do
        interface "eth0", zone: :wan
        ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
      end
    end
    """)

    config = mod.config()
    assert %{network: %{mode: :ipvlan,
      netmask: 24}} = config.host
  end

  test "ipvlan generates IP pool .1 and IP pool .2-.254" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.BridgePool do
      use Erlkoenig.Stack

      host do
        ipvlan "net", parent: {:dummy, "ek_net"}, subnet: {192, 168, 5, 0, 24}
      end

      pod "x" do
        container "c", binary: "/opt/c"
      end

      attach "x", to: "net", replicas: 1
    end
    """)

    config = mod.config()
    net = config.host.network
    assert net.mode == :ipvlan
    assert net.netmask == 24

    zone = hd(config.zones)
    assert zone.pool == %{start: {192, 168, 5, 2}, stop: {192, 168, 5, 254}}
  end

  test "ipvlan network config" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.NoUplink do
      use Erlkoenig.Stack
      host do
        ipvlan "internal", parent: {:dummy, "ek_int"}, subnet: {10, 0, 0, 0, 24}
      end
    end
    """)

    net = mod.config().host.network
    assert net.mode == :ipvlan
    assert net.parent_type == :dummy
  end

  test "interface zone preserved in config" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.InterfaceZone do
      use Erlkoenig.Stack
      host do
        interface "eth0", zone: :wan
        interface "eth1", zone: :lan
        ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
      end
    end
    """)

    ifaces = mod.config().host.interfaces
    assert length(ifaces) == 2
    eth0 = Enum.find(ifaces, & &1.name == "eth0")
    assert eth0.zone == :wan
    eth1 = Enum.find(ifaces, & &1.name == "eth1")
    assert eth1.zone == :lan
  end

  test "attach replica naming: pod-index-container" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.ReplicaNaming do
      use Erlkoenig.Stack

      host do
        ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
      end

      pod "web" do
        container "nginx", binary: "/opt/nginx"
        container "sidecar", binary: "/opt/sidecar"
      end

      attach "web", to: "net0", replicas: 2
    end
    """)

    zone = hd(mod.config().zones)
    assert zone.deployments == [%{pod: "web", replicas: 2}]
    # Pod has 2 containers → 2 replicas = 4 total containers:
    # web-0-nginx, web-0-sidecar, web-1-nginx, web-1-sidecar
    pod = hd(mod.config().pods)
    assert length(pod.containers) == 2
    names = Enum.map(pod.containers, & &1.name)
    assert names == ["nginx", "sidecar"]
  end

  test "pod + attach compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.HostAttach do
      use Erlkoenig.Stack

      host do
        interface "eth0", zone: :wan
        ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
      end

      pod "web" do
        container "frontend", binary: "/opt/frontend"
        container "api", binary: "/opt/api"
      end

      attach "web", to: "net0", replicas: 3
    end
    """)

    config = mod.config()
    assert length(config.zones) == 1
    zone = hd(config.zones)
    assert zone.name == "net0"
    assert zone.deployments == [%{pod: "web", replicas: 3}]
  end

  test "multi-ipvlan three-tier" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.ThreeTier do
      use Erlkoenig.Stack

      host do
        interface "eth0", zone: :wan
        ipvlan "dmz", parent: {:dummy, "ek_dmz"}, subnet: {10, 0, 0, 0, 24}
        ipvlan "app", parent: {:dummy, "ek_app"}, subnet: {10, 0, 1, 0, 24}
        ipvlan "data", parent: {:dummy, "ek_data"}, subnet: {10, 0, 2, 0, 24}
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
        detect do
          flood over: 50, within: s(10)
          port_scan over: 20, within: m(1)
        end

        respond do
          ban_for h(1)
          suspect after: 3, distinct: :ports
        end

        allowlist [{127, 0, 0, 1}]
      end
    end
    """)

    guard = mod.config().ct_guard
    assert guard.conn_flood == {50, 10}
    assert guard.port_scan == {20, 60}
    assert guard.ban_duration == 3600
    assert guard.suspect_after == 3
    assert {127, 0, 0, 1} in guard.whitelist
  end

  test "same pod attached to multiple ipvlans" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.MultiAttach do
      use Erlkoenig.Stack

      host do
        ipvlan "region_eu", parent: {:dummy, "ek_eu"}, subnet: {10, 1, 0, 0, 24}
        ipvlan "region_us", parent: {:dummy, "ek_us"}, subnet: {10, 2, 0, 0, 24}
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
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        attach "nonexistent", to: "net0", replicas: 1
      end
      """)
    end
  end

  test "attach references unknown network raises" do
    assert_raise CompileError, ~r/unknown network/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadBridge do
        use Erlkoenig.Stack
        pod "web" do
          container "app", binary: "/opt/app"
        end
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
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
        ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
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

      attach "db", to: "net0", replicas: 1
      attach "workers", to: "net0", replicas: 5
      attach "pipeline", to: "net0", replicas: 1
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

  # ═══════════════════════════════════════════════════════════
  # publish block tests (SPEC-EK-007)
  # ═══════════════════════════════════════════════════════════

  test "publish block with single interval" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.PublishSingle do
      use Erlkoenig.Stack
      pod "web" do
        container "nginx", binary: "/opt/nginx" do
          publish interval: 2000 do
            metric :memory
            metric :cpu
          end
        end
      end
    end
    """)

    pod = hd(mod.config().pods)
    ct = hd(pod.containers)
    assert ct.publish == [%{interval: 2000, metrics: [:memory, :cpu]}]
  end

  test "publish block with multiple intervals" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.PublishMulti do
      use Erlkoenig.Stack
      pod "web" do
        container "nginx", binary: "/opt/nginx" do
          publish interval: 1000 do
            metric :memory
            metric :cpu
            metric :pids
          end
          publish interval: 30_000 do
            metric :pressure
            metric :oom_events
          end
        end
      end
    end
    """)

    pod = hd(mod.config().pods)
    ct = hd(pod.containers)
    assert length(ct.publish) == 2
    [fast, slow] = ct.publish
    assert fast == %{interval: 1000, metrics: [:memory, :cpu, :pids]}
    assert slow == %{interval: 30_000, metrics: [:pressure, :oom_events]}
  end

  test "container without publish has no publish key" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.NoPublish do
      use Erlkoenig.Stack
      pod "web" do
        container "nginx", binary: "/opt/nginx"
      end
    end
    """)

    pod = hd(mod.config().pods)
    ct = hd(pod.containers)
    refute Map.has_key?(ct, :publish)
  end

  test "publish interval below 1000ms raises" do
    assert_raise CompileError, ~r/interval must be >= 1000ms/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.PublishTooFast do
        use Erlkoenig.Stack
        pod "web" do
          container "nginx", binary: "/opt/nginx" do
            publish interval: 500 do
              metric :memory
            end
          end
        end
      end
      """)
    end
  end

  test "publish with unknown metric raises" do
    assert_raise CompileError, ~r/unknown metric.*:bandwidth/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.PublishBadMetric do
        use Erlkoenig.Stack
        pod "web" do
          container "nginx", binary: "/opt/nginx" do
            publish interval: 1000 do
              metric :bandwidth
            end
          end
        end
      end
      """)
    end
  end

  test "publish with duplicate metric raises" do
    assert_raise CompileError, ~r/duplicate metric.*:memory/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.PublishDupMetric do
        use Erlkoenig.Stack
        pod "web" do
          container "nginx", binary: "/opt/nginx" do
            publish interval: 1000 do
              metric :memory
              metric :memory
            end
          end
        end
      end
      """)
    end
  end

  test "publish with empty block raises" do
    assert_raise CompileError, ~r/at least one metric/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.PublishEmpty do
        use Erlkoenig.Stack
        pod "web" do
          container "nginx", binary: "/opt/nginx" do
            publish interval: 1000 do
            end
          end
        end
      end
      """)
    end
  end

  test "mixed containers with and without publish" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.PublishMixed do
      use Erlkoenig.Stack
      pod "stack" do
        container "nginx", binary: "/opt/nginx" do
          publish interval: 2000 do
            metric :memory
          end
        end
        container "worker", binary: "/opt/worker"
      end
    end
    """)

    pod = hd(mod.config().pods)
    [nginx, worker] = pod.containers
    assert nginx.publish == [%{interval: 2000, metrics: [:memory]}]
    refute Map.has_key?(worker, :publish)
  end

  # ═══════════════════════════════════════════════════════════
  # stream block tests (SPEC-EK-011)
  # ═══════════════════════════════════════════════════════════

  test "stream block with both channels" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.StreamBoth do
      use Erlkoenig.Stack
      pod "web", strategy: :one_for_one do
        container "api", binary: "/opt/api" do
          stream retention: {90, :days} do
            channel :stdout
            channel :stderr
          end
        end
      end
    end
    """)

    pod = hd(mod.config().pods)
    ct = hd(pod.containers)
    assert ct.stream == %{channels: [:stdout, :stderr], retention_days: 90}
  end

  test "stream block stderr only with max_bytes" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.StreamStderr do
      use Erlkoenig.Stack
      pod "web", strategy: :one_for_one do
        container "api", binary: "/opt/api" do
          stream retention: {30, :days}, max_bytes: {5, :gb} do
            channel :stderr
          end
        end
      end
    end
    """)

    ct = hd(hd(mod.config().pods).containers)
    assert ct.stream.channels == [:stderr]
    assert ct.stream.retention_days == 30
    assert ct.stream.max_bytes == 5_368_709_120
  end

  test "stream block default retention 7 days" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.StreamDefault do
      use Erlkoenig.Stack
      pod "web", strategy: :one_for_one do
        container "api", binary: "/opt/api" do
          stream do
            channel :stdout
          end
        end
      end
    end
    """)

    ct = hd(hd(mod.config().pods).containers)
    assert ct.stream.retention_days == 7
    assert ct.stream.channels == [:stdout]
  end

  test "container without stream has no stream key" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.NoStream do
      use Erlkoenig.Stack
      pod "web", strategy: :one_for_one do
        container "api", binary: "/opt/api"
      end
    end
    """)

    ct = hd(hd(mod.config().pods).containers)
    refute Map.has_key?(ct, :stream)
  end

  test "stream with unknown channel raises" do
    assert_raise CompileError, ~r/unknown channel.*:stdin/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.StreamBadChannel do
        use Erlkoenig.Stack
        pod "web", strategy: :one_for_one do
          container "api", binary: "/opt/api" do
            stream do
              channel :stdin
            end
          end
        end
      end
      """)
    end
  end

  test "stream with duplicate channel raises" do
    assert_raise CompileError, ~r/duplicate channel.*:stderr/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.StreamDupChannel do
        use Erlkoenig.Stack
        pod "web", strategy: :one_for_one do
          container "api", binary: "/opt/api" do
            stream do
              channel :stderr
              channel :stderr
            end
          end
        end
      end
      """)
    end
  end

  test "stream with empty block raises" do
    assert_raise CompileError, ~r/at least one channel/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.StreamEmpty do
        use Erlkoenig.Stack
        pod "web", strategy: :one_for_one do
          container "api", binary: "/opt/api" do
            stream do
            end
          end
        end
      end
      """)
    end
  end

  test "two stream blocks per container raises" do
    assert_raise CompileError, ~r/only one stream block/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.StreamDouble do
        use Erlkoenig.Stack
        pod "web", strategy: :one_for_one do
          container "api", binary: "/opt/api" do
            stream do
              channel :stdout
            end
            stream do
              channel :stderr
            end
          end
        end
      end
      """)
    end
  end

  test "stream with publish in same container" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.StreamAndPublish do
      use Erlkoenig.Stack
      pod "web", strategy: :one_for_one do
        container "api", binary: "/opt/api" do
          publish interval: 2000 do
            metric :memory
          end
          stream retention: {90, :days} do
            channel :stdout
            channel :stderr
          end
        end
      end
    end
    """)

    ct = hd(hd(mod.config().pods).containers)
    assert ct.publish == [%{interval: 2000, metrics: [:memory]}]
    assert ct.stream == %{channels: [:stdout, :stderr], retention_days: 90}
  end
end
