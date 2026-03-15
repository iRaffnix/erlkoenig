defmodule Erlkoenig.ContainerDslTest do
  use ExUnit.Case, async: true

  # --- DSL test modules ---

  defmodule SimpleCluster do
    use Erlkoenig.Container

    container :web do
      binary "/opt/bin/web_server"
      ip {10, 0, 0, 10}
      ports [{8080, 80}]
      env %{"PORT" => "80"}
    end

    container :worker do
      binary "/opt/bin/worker"
      ip {10, 0, 0, 20}
      args ["--threads", "4"]
    end
  end

  defmodule WithFirewall do
    use Erlkoenig.Container

    container :app do
      binary "/opt/bin/app"
      ip {10, 0, 0, 10}
      firewall do
        accept :established
        accept :icmp
        accept_udp 53
        accept :all
      end
    end

    container :api do
      binary "/opt/bin/api"
      ip {10, 0, 0, 20}
      firewall do
        accept :established
        accept :icmp
        accept_tcp 443
      end
    end
  end

  defmodule SingleContainer do
    use Erlkoenig.Container

    container :echo do
      binary "/usr/bin/echo"
      ip {10, 0, 0, 5}
    end
  end

  defmodule WithNewFeatures do
    use Erlkoenig.Container

    container :restarter do
      binary "/opt/bin/server"
      ip {10, 0, 0, 10}
      restart {:on_failure, 3}
    end

    container :injected do
      binary "/opt/bin/app"
      ip {10, 0, 0, 20}
      files %{"/etc/hostname" => "erlkoenig-test\n", "/etc/config.json" => ~s({"port": 8080}\n)}
    end

    container :named do
      binary "/opt/bin/server"
      ip {10, 0, 0, 30}
      dns_name "webserver"
    end

    container :with_single_file do
      binary "/opt/bin/app"
      ip {10, 0, 0, 40}
      file "/etc/hostname", "single-file-test\n"
    end
  end

  defmodule WithZonesAndHealth do
    use Erlkoenig.Container

    container :dmz_web do
      binary "/opt/bin/web"
      ip {10, 0, 1, 10}
      zone :dmz
      ports [{443, 443}]
      health_check port: 443, interval: 5000, retries: 3
    end

    container :internal_db do
      binary "/opt/bin/db"
      ip {10, 0, 2, 10}
      zone :internal
    end

    container :default_app do
      binary "/opt/bin/app"
      ip {10, 0, 0, 10}
    end
  end

  # --- Tests ---

  describe "Container DSL" do
    test "SimpleCluster defines two containers" do
      containers = SimpleCluster.containers()
      assert length(containers) == 2
    end

    test "SimpleCluster containers have correct properties" do
      containers = SimpleCluster.containers()
      web = Enum.find(containers, &(&1.name == "web"))
      worker = Enum.find(containers, &(&1.name == "worker"))

      assert web.binary == "/opt/bin/web_server"
      assert web.ip == {10, 0, 0, 10}
      assert web.ports == [{8080, 80}]
      assert web.env == %{"PORT" => "80"}

      assert worker.binary == "/opt/bin/worker"
      assert worker.ip == {10, 0, 0, 20}
      assert worker.args == ["--threads", "4"]
    end

    test "spawn_opts returns {name, binary, opts} tuples" do
      opts_list = SimpleCluster.spawn_opts()
      assert length(opts_list) == 2
      {name, binary, opts} = Enum.find(opts_list, fn {n, _, _} -> n == "web" end)
      assert name == "web"
      assert binary == "/opt/bin/web_server"
      assert opts.ip == {10, 0, 0, 10}
    end

    test "firewall block produces chain with rules" do
      containers = WithFirewall.containers()
      app = Enum.find(containers, &(&1.name == "app"))

      assert Map.has_key?(app, :firewall)
      assert is_map(app.firewall)
      [chain] = app.firewall.chains
      assert {:udp_accept, 53} in chain.rules
      assert :accept in chain.rules
    end

    test "firewall block with strict rules (no accept :all)" do
      containers = WithFirewall.containers()
      api = Enum.find(containers, &(&1.name == "api"))

      assert Map.has_key?(api, :firewall)
      [chain] = api.firewall.chains
      assert {:tcp_accept, 443} in chain.rules
      refute :accept in chain.rules
    end

    test "SingleContainer has one entry" do
      assert length(SingleContainer.containers()) == 1
      [ct] = SingleContainer.containers()
      assert ct.name == "echo"
      assert ct.binary == "/usr/bin/echo"
    end

    test "restart policy in DSL" do
      containers = WithNewFeatures.containers()
      restarter = Enum.find(containers, &(&1.name == "restarter"))
      assert restarter.restart == {:on_failure, 3}
    end

    test "files injection in DSL" do
      containers = WithNewFeatures.containers()
      injected = Enum.find(containers, &(&1.name == "injected"))
      assert injected.files["/etc/hostname"] == "erlkoenig-test\n"
      assert injected.files["/etc/config.json"] =~ "8080"
    end

    test "dns_name overrides definition name" do
      containers = WithNewFeatures.containers()
      named = Enum.find(containers, &(&1.ip == {10, 0, 0, 30}))
      assert named.name == "webserver"
    end

    test "single file macro" do
      containers = WithNewFeatures.containers()
      ct = Enum.find(containers, &(&1.name == "with_single_file"))
      assert ct.files["/etc/hostname"] == "single-file-test\n"
    end

    test "name is included in spawn_opts for DNS" do
      opts_list = SimpleCluster.spawn_opts()
      {_name, _binary, opts} = Enum.find(opts_list, fn {n, _, _} -> n == "web" end)
      assert opts.name == "web"
    end

    test "zone macro sets zone on container" do
      containers = WithZonesAndHealth.containers()
      dmz = Enum.find(containers, &(&1.name == "dmz_web"))
      internal = Enum.find(containers, &(&1.name == "internal_db"))
      default_app = Enum.find(containers, &(&1.name == "default_app"))

      assert dmz.zone == :dmz
      assert internal.zone == :internal
      refute Map.has_key?(default_app, :zone)
    end

    test "health_check macro sets health check" do
      containers = WithZonesAndHealth.containers()
      dmz = Enum.find(containers, &(&1.name == "dmz_web"))
      assert dmz.health_check == %{port: 443, interval: 5000, retries: 3}
    end

    test "zone is included in spawn_opts" do
      opts_list = WithZonesAndHealth.spawn_opts()
      {_, _, opts} = Enum.find(opts_list, fn {n, _, _} -> n == "dmz_web" end)
      assert opts.zone == :dmz
    end

    test "zone is omitted from spawn_opts when not set" do
      opts_list = WithZonesAndHealth.spawn_opts()
      {_, _, opts} = Enum.find(opts_list, fn {n, _, _} -> n == "default_app" end)
      refute Map.has_key?(opts, :zone)
    end

    test "write! creates term file" do
      path = Path.join(System.tmp_dir!(), "erlkoenig_ct_test_#{:rand.uniform(100000)}.term")
      SimpleCluster.write!(path)
      assert File.exists?(path)
      content = File.read!(path)
      assert content =~ "web_server"
      assert content =~ "worker"
      File.rm!(path)
    end
  end
end
