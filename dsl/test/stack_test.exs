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
    assert %{network: %{mode: :ipvlan, netmask: 24}} = config.host
  end

  test "ipvlan generates IP pool .2-.254" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Pool do
      use Erlkoenig.Stack

      host do
        ipvlan "net", parent: {:dummy, "ek_net"}, subnet: {192, 168, 5, 0, 24}
      end

      pod "x", strategy: :one_for_one do
        container "c",
          binary: "/opt/c",
          zone: "net",
          replicas: 1,
          restart: :permanent
      end
    end
    """)

    zone = hd(mod.config().zones)
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

  # ═══════════════════════════════════════════════════════════
  # pod + container — new inline form
  # ═══════════════════════════════════════════════════════════

  test "container carries zone and replicas inline" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Inline do
      use Erlkoenig.Stack

      host do
        ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
      end

      pod "web", strategy: :one_for_one do
        container "nginx",
          binary: "/opt/nginx",
          zone: "net0",
          replicas: 2,
          restart: :permanent

        container "sidecar",
          binary: "/opt/sidecar",
          zone: "net0",
          replicas: 2,
          restart: :permanent
      end
    end
    """)

    pod = hd(mod.config().pods)
    assert pod.name == "web"
    assert length(pod.containers) == 2
    nginx = Enum.find(pod.containers, & &1.name == "nginx")
    assert nginx.zone == "net0"
    assert nginx.replicas == 2
    assert nginx.restart == :permanent
  end

  test "multi-ipvlan three-tier: one pod bracket, per-container zones" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.ThreeTier do
      use Erlkoenig.Stack

      host do
        interface "eth0", zone: :wan
        ipvlan "dmz",  parent: {:dummy, "ek_dmz"},  subnet: {10, 0, 0, 0, 24}
        ipvlan "app",  parent: {:dummy, "ek_app"},  subnet: {10, 0, 1, 0, 24}
        ipvlan "data", parent: {:dummy, "ek_data"}, subnet: {10, 0, 2, 0, 24}
      end

      pod "three_tier", strategy: :one_for_one do
        container "nginx",
          binary: "/opt/nginx",
          zone: "dmz",  replicas: 3, restart: :permanent

        container "api",
          binary: "/opt/api",
          zone: "app",  replicas: 2, restart: :permanent

        container "postgres",
          binary: "/opt/pg",
          zone: "data", replicas: 1, restart: :permanent
      end
    end
    """)

    config = mod.config()
    assert length(config.zones) == 3

    pod = hd(config.pods)
    zones_by_ct = Map.new(pod.containers, &{&1.name, &1.zone})
    assert zones_by_ct == %{"nginx" => "dmz", "api" => "app", "postgres" => "data"}

    replicas_by_ct = Map.new(pod.containers, &{&1.name, &1.replicas})
    assert replicas_by_ct == %{"nginx" => 3, "api" => 2, "postgres" => 1}
  end

  test "container zone references unknown ipvlan raises" do
    assert_raise CompileError, ~r/zone "missing" is not declared/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadZone do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web", strategy: :one_for_one do
          container "app",
            binary: "/opt/app",
            zone: "missing",
            replicas: 1,
            restart: :permanent
        end
      end
      """)
    end
  end

  test "pod with duplicate container names raises" do
    assert_raise CompileError, ~r/duplicate container/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.DupCt do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "bad", strategy: :one_for_one do
          container "web",
            binary: "/a", zone: "net0", replicas: 1, restart: :permanent
          container "web",
            binary: "/b", zone: "net0", replicas: 1, restart: :permanent
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
        pod "empty", strategy: :one_for_one do
        end
      end
      """)
    end
  end

  test "pod strategy is required" do
    assert_raise CompileError, ~r/strategy: is required/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.NoStrategy do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web" do
          container "app",
            binary: "/opt/app", zone: "net0", replicas: 1, restart: :permanent
        end
      end
      """)
    end
  end

  test "pod strategy :one_for_all" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.LinkedPod do
      use Erlkoenig.Stack
      host do
        ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "backend", strategy: :one_for_all do
        container "db",
          binary: "/opt/db",  zone: "net0", replicas: 1, restart: :permanent
        container "api",
          binary: "/opt/api", zone: "net0", replicas: 1, restart: :permanent
      end
    end
    """)

    pod = hd(mod.config().pods)
    assert pod.name == "backend"
    assert pod.strategy == :one_for_all
    assert length(pod.containers) == 2
  end

  test "pod strategy :rest_for_one preserves container order" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.OrderedPod do
      use Erlkoenig.Stack
      host do
        ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "pipeline", strategy: :rest_for_one do
        container "db",
          binary: "/opt/db",    zone: "net0", replicas: 1, restart: :permanent
        container "api",
          binary: "/opt/api",   zone: "net0", replicas: 1, restart: :permanent
        container "proxy",
          binary: "/opt/proxy", zone: "net0", replicas: 1, restart: :permanent
      end
    end
    """)

    pod = hd(mod.config().pods)
    assert pod.strategy == :rest_for_one
    names = Enum.map(pod.containers, & &1.name)
    assert names == ["db", "api", "proxy"]
  end

  test "pod strategy invalid value raises" do
    assert_raise CompileError, ~r/invalid strategy.*:banana/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadStrategy do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "bad", strategy: :banana do
          container "x",
            binary: "/opt/x", zone: "net0", replicas: 1, restart: :permanent
        end
      end
      """)
    end
  end

  test "container without binary raises" do
    assert_raise CompileError, ~r/binary.*is required/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.NoBin do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "bad", strategy: :one_for_one do
          container "web",
            image: "foo", zone: "net0", replicas: 1, restart: :permanent
        end
      end
      """)
    end
  end

  test "container without zone raises" do
    assert_raise CompileError, ~r/zone.*is required/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.NoZone do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "bad", strategy: :one_for_one do
          container "web",
            binary: "/opt/web", replicas: 1, restart: :permanent
        end
      end
      """)
    end
  end

  test "container without replicas raises" do
    assert_raise CompileError, ~r/replicas.*is required/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.NoReplicas do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "bad", strategy: :one_for_one do
          container "web",
            binary: "/opt/web", zone: "net0", restart: :permanent
        end
      end
      """)
    end
  end

  test "container without restart raises" do
    assert_raise CompileError, ~r/restart.*is required/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.NoRestart do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "bad", strategy: :one_for_one do
          container "web",
            binary: "/opt/web", zone: "net0", replicas: 1
        end
      end
      """)
    end
  end

  test "container replicas must be positive integer" do
    assert_raise CompileError, ~r/replicas.*positive integer/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadReplicas do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "bad", strategy: :one_for_one do
          container "web",
            binary: "/opt/web", zone: "net0", replicas: 0, restart: :permanent
        end
      end
      """)
    end
  end

  test "container invalid restart raises" do
    assert_raise CompileError, ~r/invalid restart/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadRestart do
        use Erlkoenig.Stack
        host do
          ipvlan "net0", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "bad", strategy: :one_for_one do
          container "web",
            binary: "/opt/web", zone: "net0", replicas: 1, restart: :always
        end
      end
      """)
    end
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

  # ═══════════════════════════════════════════════════════════
  # publish block tests (SPEC-EK-007)
  # ═══════════════════════════════════════════════════════════

  test "publish block with single interval" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.PublishSingle do
      use Erlkoenig.Stack
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "web", strategy: :one_for_one do
        container "nginx",
          binary: "/opt/nginx",
          zone: "net", replicas: 1, restart: :permanent do
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
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "web", strategy: :one_for_one do
        container "nginx",
          binary: "/opt/nginx",
          zone: "net", replicas: 1, restart: :permanent do
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
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "web", strategy: :one_for_one do
        container "nginx",
          binary: "/opt/nginx",
          zone: "net", replicas: 1, restart: :permanent
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
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web", strategy: :one_for_one do
          container "nginx",
            binary: "/opt/nginx",
            zone: "net", replicas: 1, restart: :permanent do
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
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web", strategy: :one_for_one do
          container "nginx",
            binary: "/opt/nginx",
            zone: "net", replicas: 1, restart: :permanent do
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
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web", strategy: :one_for_one do
          container "nginx",
            binary: "/opt/nginx",
            zone: "net", replicas: 1, restart: :permanent do
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
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web", strategy: :one_for_one do
          container "nginx",
            binary: "/opt/nginx",
            zone: "net", replicas: 1, restart: :permanent do
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
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "stack", strategy: :one_for_one do
        container "nginx",
          binary: "/opt/nginx",
          zone: "net", replicas: 1, restart: :permanent do
          publish interval: 2000 do
            metric :memory
          end
        end
        container "worker",
          binary: "/opt/worker",
          zone: "net", replicas: 1, restart: :permanent
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
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "web", strategy: :one_for_one do
        container "api",
          binary: "/opt/api",
          zone: "net", replicas: 1, restart: :permanent do
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
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "web", strategy: :one_for_one do
        container "api",
          binary: "/opt/api",
          zone: "net", replicas: 1, restart: :permanent do
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
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "web", strategy: :one_for_one do
        container "api",
          binary: "/opt/api",
          zone: "net", replicas: 1, restart: :permanent do
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
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "web", strategy: :one_for_one do
        container "api",
          binary: "/opt/api",
          zone: "net", replicas: 1, restart: :permanent
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
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web", strategy: :one_for_one do
          container "api",
            binary: "/opt/api",
            zone: "net", replicas: 1, restart: :permanent do
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
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web", strategy: :one_for_one do
          container "api",
            binary: "/opt/api",
            zone: "net", replicas: 1, restart: :permanent do
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
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web", strategy: :one_for_one do
          container "api",
            binary: "/opt/api",
            zone: "net", replicas: 1, restart: :permanent do
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
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "web", strategy: :one_for_one do
          container "api",
            binary: "/opt/api",
            zone: "net", replicas: 1, restart: :permanent do
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
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "web", strategy: :one_for_one do
        container "api",
          binary: "/opt/api",
          zone: "net", replicas: 1, restart: :permanent do
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

  # ─── volume macro ───────────────────────────────────────

  test "volume with persist only (rw, no opts)" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.VolPlain do
      use Erlkoenig.Stack
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "app", strategy: :one_for_one do
        container "svc",
          binary: "/opt/svc",
          zone: "net", replicas: 1, restart: :permanent do
          volume "/data", persist: "svc-data"
        end
      end
    end
    """)

    ct = hd(hd(mod.config().pods).containers)
    assert ct.volumes == [
      %{container: "/data", persist: "svc-data",
        read_only: false, ephemeral: false}
    ]
  end

  test "ephemeral: true flows into the volume term" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.VolEphemeral do
      use Erlkoenig.Stack
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "app", strategy: :one_for_one do
        container "svc",
          binary: "/opt/svc",
          zone: "net", replicas: 1, restart: :permanent do
          volume "/scratch", persist: "scratch", ephemeral: true
          volume "/data",    persist: "data"
        end
      end
    end
    """)

    vols = hd(hd(mod.config().pods).containers).volumes
    [scratch, data] = vols
    assert scratch.ephemeral == true
    assert data.ephemeral == false
  end

  test "ephemeral: non-boolean raises ArgumentError" do
    assert_raise ArgumentError, ~r/expected a boolean/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.VolBadEphemeral do
        use Erlkoenig.Stack
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "app", strategy: :one_for_one do
          container "svc",
            binary: "/opt/svc",
            zone: "net", replicas: 1, restart: :permanent do
            volume "/x", persist: "p", ephemeral: "yes"
          end
        end
      end
      """)
    end
  end

  test "volume with opts string survives into term" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.VolOpts do
      use Erlkoenig.Stack
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "app", strategy: :one_for_one do
        container "svc",
          binary: "/opt/svc",
          zone: "net", replicas: 1, restart: :permanent do
          volume "/uploads", persist: "svc-uploads",
                             opts: "rw,nosuid,nodev,noexec"
        end
      end
    end
    """)

    ct = hd(hd(mod.config().pods).containers)
    [vol] = ct.volumes
    assert vol.container == "/uploads"
    assert vol.persist == "svc-uploads"
    assert vol.opts == "rw,nosuid,nodev,noexec"
  end

  test "volume with read_only: true (legacy boolean)" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.VolRo do
      use Erlkoenig.Stack
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "app", strategy: :one_for_one do
        container "svc",
          binary: "/opt/svc",
          zone: "net", replicas: 1, restart: :permanent do
          volume "/etc/app", persist: "svc-cfg", read_only: true
        end
      end
    end
    """)

    [vol] = hd(hd(mod.config().pods).containers).volumes
    assert vol.read_only == true
  end

  test "volume opts: non-binary raises ArgumentError" do
    assert_raise ArgumentError, ~r/expected a binary string/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.VolBadOpts do
        use Erlkoenig.Stack
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "app", strategy: :one_for_one do
          container "svc",
            binary: "/opt/svc",
            zone: "net", replicas: 1, restart: :permanent do
            volume "/x", persist: "p", opts: :not_a_string
          end
        end
      end
      """)
    end
  end

  test "volume outside a container raises CompileError" do
    assert_raise CompileError, ~r/inside a container block/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.VolStray do
        use Erlkoenig.Stack
        host do
          ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "app", strategy: :one_for_one do
          volume "/nope", persist: "nope"
        end
      end
      """)
    end
  end

  test "multiple volumes preserve declaration order" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.VolMany do
      use Erlkoenig.Stack
      host do
        ipvlan "net", parent: {:dummy, "ek"}, subnet: {10, 0, 0, 0, 24}
      end
      pod "app", strategy: :one_for_one do
        container "svc",
          binary: "/opt/svc",
          zone: "net", replicas: 1, restart: :permanent do
          volume "/a", persist: "first"
          volume "/b", persist: "second", read_only: true
          volume "/c", persist: "third",  opts: "ro,nosuid"
        end
      end
    end
    """)

    vols = hd(hd(mod.config().pods).containers).volumes
    assert Enum.map(vols, & &1.container) == ["/a", "/b", "/c"]
    assert Enum.map(vols, & &1.persist)   == ["first", "second", "third"]
  end
end
