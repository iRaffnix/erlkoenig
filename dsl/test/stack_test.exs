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

  test "host firewall only" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.HostOnly do
      use Erlkoenig.Stack

      firewall "host" do
        counters [:ssh, :dropped]
        set "blocklist", :ipv4_addr

        chain "input", hook: :input, policy: :drop do
          rule :accept, ct: :established
          rule :accept, iif: "lo"
          rule :accept, tcp: 22, limit: {25, burst: 5}, counter: :ssh
          rule :drop, set: "blocklist", counter: :dropped
        end
      end
    end
    """)

    config = mod.config()
    assert config.firewall.table == "host"
    assert length(config.firewall.chains) == 1
    assert config.firewall.counters == ["ssh", "dropped"]
    assert length(config.firewall.sets) == 1

    chain = hd(config.firewall.chains)
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
    assert frontend.binary == "/opt/frontend"
    assert frontend.firewall.chains |> hd() |> Map.get(:name) == "inbound"
    assert length(frontend.firewall.chains |> hd() |> Map.get(:rules)) == 3

    assert api.name == "api"

    fwd = hd(pod.chains)
    assert fwd.name == "forward"
    assert fwd.policy == :drop
    assert length(fwd.rules) == 2
  end

  test "zone with chain, deploy and steer" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.ZoneDeploy do
      use Erlkoenig.Stack

      pod "webstack" do
        container "frontend", binary: "/opt/frontend"
        container "api", binary: "/opt/api"
      end

      zone "production", subnet: {10, 0, 0, 0} do
        chain "forward", policy: :drop do
          rule :accept, ct: :established
          rule :accept, udp: 53, oif: "ek_br_production"
          rule :masquerade, oif: "eth0"
          rule :drop
        end

        deploy "webstack", replicas: 3

        steer {178, 104, 16, 107}, port: 443, proto: :tcp,
          backends: ["webstack.frontend"]
      end
    end
    """)

    config = mod.config()
    zone = hd(config.zones)
    assert zone.name == "production"
    assert zone.subnet == {10, 0, 0, 0}

    assert length(zone.chains) == 1
    fwd = hd(zone.chains)
    assert fwd.name == "forward"
    assert length(fwd.rules) == 4

    assert zone.deployments == [%{pod: "webstack", replicas: 3}]

    assert length(zone.steers) == 1
    steer = hd(zone.steers)
    assert steer.vip == {178, 104, 16, 107}
    assert steer.port == 443
    assert steer.proto == :tcp
  end

  test "guard compiles with watch_set" do
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
    assert guard.port_scan == {20, 60}
    assert guard.ban_duration == 3600
    assert {127, 0, 0, 1} in guard.whitelist
  end

  test "ct_mark match vs ct_mark_set statement" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.CtMark do
      use Erlkoenig.Stack

      firewall "test" do
        chain "input", hook: :input, policy: :drop do
          rule :accept, ct_mark: 0x42
          rule :accept, tcp: 22, ct_mark_set: 0x42
        end
      end
    end
    """)

    chain = hd(mod.config().firewall.chains)
    [match_rule, set_rule] = chain.rules

    # ct_mark is a match
    assert {:rule, :accept, %{ct_mark: 0x42}} = match_rule
    # ct_mark_set is a statement (separate key)
    assert {:rule, :accept, %{ct_mark_set: 0x42, tcp: 22}} = set_rule
  end

  test "advanced nft objects: meter, quota, flowtable, vmap" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.AdvancedNft do
      use Erlkoenig.Stack

      firewall "host" do
        counters [:ssh, :dropped]
        set "blocklist", :ipv4_addr
        vmap "port_dispatch", :inet_service, entries: [
          {22, jump: "ssh_chain"},
          {80, :accept}
        ]
        flowtable "ft0", devices: ["eth0"], priority: -100
        quota "daily", bytes: 10_000_000_000, mode: :over
        meter "ssh_limit", key: :saddr, limit: {5, burst: 3}

        chain "input", hook: :input, policy: :drop do
          rule :accept, ct: :established
          rule :accept, vmap: "port_dispatch"
          rule :drop, set: "blocklist"
        end

        chain "ssh_chain" do
          rule :accept, tcp: 22, meter: "ssh_limit", counter: :ssh
          rule :drop
        end
      end
    end
    """)

    fw = mod.config().firewall
    assert fw.table == "host"

    # vmap
    assert length(fw.vmaps) == 1
    vmap = hd(fw.vmaps)
    assert vmap.name == "port_dispatch"
    assert {22, {:jump, "ssh_chain"}} in vmap.entries

    # flowtable
    assert length(fw.flowtables) == 1
    ft = hd(fw.flowtables)
    assert ft.name == "ft0"
    assert ft.devices == ["eth0"]

    # quota
    assert length(fw.quotas) == 1
    q = hd(fw.quotas)
    assert q.name == "daily"
    assert q.bytes == 10_000_000_000

    # meter
    assert length(fw.meters) == 1
    m = hd(fw.meters)
    assert m.name == "ssh_limit"
    assert m.key == :saddr
    assert m.rate == 5
    assert m.burst == 3
  end

  test "zone without rules is isolated" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Isolated do
      use Erlkoenig.Stack

      pod "app" do
        container "web", binary: "/opt/web"
      end

      zone "dmz", subnet: {10, 0, 0, 0} do
        deploy "app", replicas: 1
      end
    end
    """)

    zone = hd(mod.config().zones)
    assert zone.name == "dmz"
    # No chains = no network access
    refute Map.has_key?(zone, :chains)
    assert zone.deployments == [%{pod: "app", replicas: 1}]
  end

  test "deploy references unknown pod raises" do
    assert_raise CompileError, ~r/unknown pod/, fn ->
      Code.compile_string(~S"""
      defmodule TestStack.BadDeploy do
        use Erlkoenig.Stack
        zone "apps" do
          deploy "nonexistent", replicas: 1
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

  test "full stack: firewall + pod + zone + guard + watch" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestStack.Full do
      use Erlkoenig.Stack

      firewall "host" do
        counters [:ssh, :dropped]
        set "blocklist", :ipv4_addr

        chain "input", hook: :input, policy: :drop do
          rule :accept, ct: :established
          rule :accept, tcp: 22, counter: :ssh
          rule :drop, set: "blocklist", counter: :dropped
        end
      end

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
          rule :drop
        end
      end

      zone "production", subnet: {10, 0, 0, 0} do
        chain "forward", policy: :drop do
          rule :accept, ct: :established
          rule :accept, udp: 53, oif: "ek_br_production"
          rule :masquerade, oif: "eth0"
          rule :drop
        end

        deploy "webstack", replicas: 5
      end

      guard do
        detect :conn_flood, threshold: 50, window: 10
        ban_duration 3600
        whitelist {127, 0, 0, 1}
      end

      watch :metrics do
      end
    end
    """)

    config = mod.config()
    assert Map.has_key?(config, :firewall)
    assert Map.has_key?(config, :pods)
    assert Map.has_key?(config, :zones)
    assert Map.has_key?(config, :ct_guard)

    assert config.firewall.table == "host"
    assert length(config.pods) == 1
    assert hd(config.pods).name == "webstack"
    assert length(config.zones) == 1
    zone = hd(config.zones)
    assert zone.deployments == [%{pod: "webstack", replicas: 5}]
  end
end
