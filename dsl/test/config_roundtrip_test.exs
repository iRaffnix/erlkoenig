defmodule Erlkoenig.ConfigRoundtripTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Tests that DSL -> term -> file:consult produces valid configs
  that erlkoenig_config.erl can parse.
  """

  defmodule TestCluster do
    use Erlkoenig.DSL

    defaults do
      firewall :standard
    end

    container :alpha do
      binary "/opt/bin/alpha"
      ip {10, 0, 0, 10}
      ports [{9080, 80}]
      limits cpu: 2, memory: "256M"
      firewall :strict, allow_tcp: [80]
    end

    container :beta do
      binary "/opt/bin/beta"
      ip {10, 0, 0, 20}
    end

    watch :monitor do
      counter :http, :pps, threshold: 5000
      on_alert :log
    end

    guard do
      detect :conn_flood, threshold: 50, window: 10
    end
  end

  # Covers all 11 use cases from the live test scripts
  defmodule FullUseCases do
    use Erlkoenig.DSL

    # 01: Lifecycle
    container :lifecycle do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-sleeper"
      ip {10, 0, 0, 1}
      args ["5"]
    end

    # 02: Networking
    container :echo_net do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
      ip {10, 0, 0, 10}
      args ["7001"]
    end

    # 03: Port forwarding
    container :echo_ports do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
      ip {10, 0, 0, 20}
      args ["7777"]
      ports [{9080, 7777}]
    end

    # 04: Memory limits
    container :mem_limited do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-sleeper"
      ip {10, 0, 0, 30}
      args ["30"]
      limits memory: "32M"
    end

    # 05: PID limits
    container :pid_limited do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-sleeper"
      ip {10, 0, 0, 40}
      args ["30"]
      limits pids: 10
    end

    # 06: Restart
    container :restarter do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-sleeper"
      ip {10, 0, 0, 50}
      args ["1"]
      restart {:on_failure, 3}
    end

    # 07: Seccomp
    container :seccomp_echo do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
      ip {10, 0, 0, 60}
      args ["7777"]
      seccomp :standard
    end

    # 08: File injection
    container :file_inject do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-sleeper"
      ip {10, 0, 0, 70}
      args ["30"]
      files %{
        "/etc/hostname" => "erlkoenig-test-container\n",
        "/etc/config.json" => ~s({"port": 8080, "debug": true}\n)
      }
    end

    # 09: DNS
    container :webserver do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
      ip {10, 0, 0, 80}
      args ["7001"]
    end

    container :database do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
      ip {10, 0, 0, 81}
      args ["7002"]
    end

    # 10: Firewall
    container :fw_open do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
      ip {10, 0, 0, 90}
      args ["7001"]
      firewall :standard
    end

    container :fw_strict do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-echo_server"
      ip {10, 0, 0, 91}
      args ["7002"]
      firewall :strict, allow_tcp: [7002]
    end

    # 11: Output capture (just needs binary + ip)
    container :output_ct do
      binary "/usr/lib/erlkoenig/demo/test-erlkoenig-sleeper"
      ip {10, 0, 0, 100}
      args ["2"]
    end
  end

  describe "roundtrip" do
    test "write -> consult produces valid Erlang map" do
      path = Path.join(System.tmp_dir!(), "erlkoenig_rt_#{:rand.uniform(100000)}.term")

      # Build the full config term (like mix erlkoenig.compile does)
      config = %{
        containers: TestCluster.containers(),
        watches: TestCluster.watches(),
        guard: TestCluster.guard_config()
      }

      formatted = :io_lib.format(~c"~tp.~n", [config])
      File.write!(path, formatted)

      # Read back with file:consult (like erlkoenig_config:parse/1)
      {:ok, [term]} = :file.consult(String.to_charlist(path))

      # Verify structure
      assert is_map(term)
      assert length(term.containers) == 2

      # Verify container alpha
      alpha = Enum.find(term.containers, fn c -> c.name == "alpha" end)
      assert alpha.binary == "/opt/bin/alpha"
      assert alpha.ip == {10, 0, 0, 10}
      assert alpha.ports == [{9080, 80}]
      assert alpha.limits.cpu == 2
      assert alpha.limits.memory == 256 * 1_048_576
      assert is_map(alpha.firewall)

      # Verify firewall term
      [chain] = alpha.firewall.chains
      assert chain.policy == :drop
      assert {:tcp_accept, 80} in chain.rules

      # Verify beta inherited :standard default
      beta = Enum.find(term.containers, fn c -> c.name == "beta" end)
      [beta_chain] = beta.firewall.chains
      assert :accept in beta_chain.rules

      # Verify watches
      assert length(term.watches) == 1
      [w] = term.watches
      assert w.name == "monitor"

      # Verify guard
      assert term.guard.conn_flood == {50, 10}

      File.rm!(path)
    end

    test "spawn_opts format is compatible" do
      opts_list = TestCluster.spawn_opts()
      assert length(opts_list) == 2

      {name, binary, opts} = hd(opts_list)
      assert name == "alpha"
      assert binary == "/opt/bin/alpha"

      # These are the keys erlkoenig:spawn/2 expects
      assert Map.has_key?(opts, :ip)
      assert Map.has_key?(opts, :ports)
      assert Map.has_key?(opts, :firewall)
      assert Map.has_key?(opts, :limits)
    end
  end

  describe "full use case roundtrip" do
    test "all 13 containers survive write -> consult" do
      path = Path.join(System.tmp_dir!(), "erlkoenig_full_#{:rand.uniform(100000)}.term")

      config = %{containers: FullUseCases.containers()}
      formatted = :io_lib.format(~c"~tp.~n", [config])
      File.write!(path, formatted)

      {:ok, [term]} = :file.consult(String.to_charlist(path))
      containers = term.containers
      assert length(containers) == 13

      File.rm!(path)
    end

    test "restart policy roundtrips" do
      containers = FullUseCases.containers()
      restarter = Enum.find(containers, &(&1.name == "restarter"))
      assert restarter.restart == {:on_failure, 3}

      # Roundtrip through file
      path = Path.join(System.tmp_dir!(), "erlkoenig_restart_#{:rand.uniform(100000)}.term")
      formatted = :io_lib.format(~c"~tp.~n", [%{containers: [restarter]}])
      File.write!(path, formatted)
      {:ok, [term]} = :file.consult(String.to_charlist(path))
      [ct] = term.containers
      assert ct.restart == {:on_failure, 3}
      File.rm!(path)
    end

    test "files roundtrip" do
      containers = FullUseCases.containers()
      ct = Enum.find(containers, &(&1.name == "file_inject"))
      assert ct.files["/etc/hostname"] == "erlkoenig-test-container\n"

      path = Path.join(System.tmp_dir!(), "erlkoenig_files_#{:rand.uniform(100000)}.term")
      formatted = :io_lib.format(~c"~tp.~n", [%{containers: [ct]}])
      File.write!(path, formatted)
      {:ok, [term]} = :file.consult(String.to_charlist(path))
      [rt] = term.containers
      assert rt.files["/etc/hostname"] == "erlkoenig-test-container\n"
      assert rt.files["/etc/config.json"] =~ "8080"
      File.rm!(path)
    end

    test "DNS names roundtrip (name in spawn_opts)" do
      containers = FullUseCases.containers()
      ws = Enum.find(containers, &(&1.name == "webserver"))
      db = Enum.find(containers, &(&1.name == "database"))
      assert ws.ip == {10, 0, 0, 80}
      assert db.ip == {10, 0, 0, 81}

      path = Path.join(System.tmp_dir!(), "erlkoenig_dns_#{:rand.uniform(100000)}.term")
      formatted = :io_lib.format(~c"~tp.~n", [%{containers: [ws, db]}])
      File.write!(path, formatted)
      {:ok, [term]} = :file.consult(String.to_charlist(path))
      ws_rt = Enum.find(term.containers, &(&1.name == "webserver"))
      db_rt = Enum.find(term.containers, &(&1.name == "database"))
      assert ws_rt.ip == {10, 0, 0, 80}
      assert db_rt.ip == {10, 0, 0, 81}
      File.rm!(path)
    end

    test "port forwarding roundtrip" do
      containers = FullUseCases.containers()
      ct = Enum.find(containers, &(&1.name == "echo_ports"))
      assert ct.ports == [{9080, 7777}]

      path = Path.join(System.tmp_dir!(), "erlkoenig_ports_#{:rand.uniform(100000)}.term")
      formatted = :io_lib.format(~c"~tp.~n", [%{containers: [ct]}])
      File.write!(path, formatted)
      {:ok, [term]} = :file.consult(String.to_charlist(path))
      [rt] = term.containers
      assert rt.ports == [{9080, 7777}]
      File.rm!(path)
    end

    test "limits roundtrip" do
      containers = FullUseCases.containers()
      ct = Enum.find(containers, &(&1.name == "mem_limited"))
      assert ct.limits.memory == 32 * 1_048_576

      path = Path.join(System.tmp_dir!(), "erlkoenig_limits_#{:rand.uniform(100000)}.term")
      formatted = :io_lib.format(~c"~tp.~n", [%{containers: [ct]}])
      File.write!(path, formatted)
      {:ok, [term]} = :file.consult(String.to_charlist(path))
      [rt] = term.containers
      assert rt.limits.memory == 32 * 1_048_576
      File.rm!(path)
    end

    test "firewall profiles roundtrip" do
      containers = FullUseCases.containers()
      strict = Enum.find(containers, &(&1.name == "fw_strict"))
      [chain] = strict.firewall.chains
      assert {:tcp_accept, 7002} in chain.rules

      path = Path.join(System.tmp_dir!(), "erlkoenig_fw_#{:rand.uniform(100000)}.term")
      formatted = :io_lib.format(~c"~tp.~n", [%{containers: [strict]}])
      File.write!(path, formatted)
      {:ok, [term]} = :file.consult(String.to_charlist(path))
      [rt] = term.containers
      [rt_chain] = rt.firewall.chains
      assert {:tcp_accept, 7002} in rt_chain.rules
      File.rm!(path)
    end

    test "seccomp roundtrip" do
      containers = FullUseCases.containers()
      ct = Enum.find(containers, &(&1.name == "seccomp_echo"))
      assert ct.seccomp.profile == :standard

      path = Path.join(System.tmp_dir!(), "erlkoenig_sec_#{:rand.uniform(100000)}.term")
      formatted = :io_lib.format(~c"~tp.~n", [%{containers: [ct]}])
      File.write!(path, formatted)
      {:ok, [term]} = :file.consult(String.to_charlist(path))
      [rt] = term.containers
      assert rt.seccomp.profile == :standard
      File.rm!(path)
    end
  end
end
