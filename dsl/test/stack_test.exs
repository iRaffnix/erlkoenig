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

  test "host with interface, bridge and chain" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.HostOnly do
      use Erlkoenig.Stack

      host do
        interface "eth0", zone: :wan
        bridge "br0", subnet: {10, 0, 0, 0, 24}, uplink: "eth0"

        chain "input", hook: :input, policy: :drop do
          rule :accept, ct: :established
          rule :accept, iif: "lo"
          rule :accept, tcp: 22, limit: {25, burst: 5}
          rule :drop, log: "HOST_DROP: "
        end
      end
    end
    """)

    config = mod.config()
    assert config.host.bridges == [%{name: "br0", subnet: {10, 0, 0, 0},
      netmask: 24, gateway: {10, 0, 0, 1}, uplink: "eth0"}]
    assert length(config.host.chains) == 1

    chain = hd(config.host.chains)
    assert chain.name == "input"
    assert chain.hook == :input
    assert chain.policy == :drop
    assert length(chain.rules) == 4
  end

  test "pod definition with containers and forward chain" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.PodDef do
      use Erlkoenig.Stack

      pod "webstack" do
        container "frontend", binary: "/opt/frontend" do
          chain "inbound", policy: :drop do
            rule :accept, ct: :established
            rule :accept, tcp: 8080
            rule :drop
          end
        end

        container "api", binary: "/opt/api" do
          chain "inbound", policy: :drop do
            rule :accept, ct: :established
            rule :accept, tcp: 4000
            rule :drop
          end
        end

        chain "forward", policy: :drop do
          rule :accept, ct: :established
          rule :drop, log: "POD_DROP: "
        end
      end
    end
    """)

    config = mod.config()
    assert length(config.pods) == 1

    pod = hd(config.pods)
    assert pod.name == "webstack"
    assert length(pod.containers) == 2
    assert length(pod.chains) == 1

    [frontend, api] = pod.containers
    assert frontend.name == "frontend"
    assert frontend.firewall.chains |> hd() |> Map.get(:name) == "inbound"

    fwd = hd(pod.chains)
    assert fwd.name == "forward"
    assert fwd.policy == :drop
  end

  test "host + pod + attach compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.HostAttach do
      use Erlkoenig.Stack

      host do
        interface "eth0", zone: :wan
        bridge "br0", subnet: {10, 0, 0, 0, 24}, uplink: "eth0"

        chain "forward", hook: :forward, policy: :drop do
          rule :accept, ct: :established
          rule :accept, iif: "eth0", oif: "web.frontend", tcp: 8080
          rule :drop
        end
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

        chain "forward", hook: :forward, policy: :drop do
          rule :accept, ct: :established
          rule :accept, iif: "eth0", oif: "web.nginx", tcp: 443
          rule :accept, iif: "web.nginx", oif: "app.api", tcp: 4000
          rule :accept, iif: "app.api", oif: "data.postgres", tcp: 5432
          rule :drop
        end
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

  test "ct_mark match vs ct_mark_set statement" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.CtMark do
      use Erlkoenig.Stack

      host do
        chain "input", hook: :input, policy: :drop do
          rule :accept, ct_mark: 0x42
          rule :accept, tcp: 22, ct_mark_set: 0x42
        end
      end
    end
    """)

    chain = hd(mod.config().host.chains)
    [match_rule, set_rule] = chain.rules
    assert {:rule, :accept, %{ct_mark: 0x42}} = match_rule
    assert {:rule, :accept, %{ct_mark_set: 0x42, tcp: 22}} = set_rule
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
