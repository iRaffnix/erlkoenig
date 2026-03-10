defmodule Erlkoenig.DslTest do
  use ExUnit.Case, async: true

  defmodule FullExample do
    use Erlkoenig.DSL

    defaults do
      firewall :standard
    end

    container :web_api do
      binary "/opt/bin/api_server"
      ip {10, 0, 0, 10}
      ports [{8080, 80}, {8443, 443}]
      env %{"PORT" => "80", "ENV" => "prod"}
      firewall :strict, allow_tcp: [80, 443]
    end

    container :worker do
      binary "/opt/bin/worker"
      ip {10, 0, 0, 20}
      args ["--threads", "4"]
    end

    container :cache do
      binary "/opt/bin/redis"
      ip {10, 0, 0, 30}
      firewall :strict, allow_tcp: [6379]
      limits cpu: 2, memory: "512M", pids: 50
      seccomp :standard
    end
  end

  describe "Erlkoenig.DSL" do
    test "defines three containers" do
      assert length(FullExample.containers()) == 3
    end

    test "web_api has explicit strict firewall" do
      [web | _] = FullExample.containers()
      assert web.name == "web_api"
      [chain] = web.firewall.chains
      assert {:tcp_accept, 80} in chain.rules
      assert {:tcp_accept, 443} in chain.rules
      refute :accept in chain.rules
    end

    test "worker inherits default standard firewall" do
      containers = FullExample.containers()
      worker = Enum.find(containers, &(&1.name == "worker"))
      [chain] = worker.firewall.chains
      assert :accept in chain.rules
      assert {:udp_accept, 53} in chain.rules
    end

    test "cache has strict with redis port" do
      containers = FullExample.containers()
      cache = Enum.find(containers, &(&1.name == "cache"))
      [chain] = cache.firewall.chains
      assert {:tcp_accept, 6379} in chain.rules
    end

    test "spawn_opts returns three tuples" do
      opts = FullExample.spawn_opts()
      assert length(opts) == 3
      {name, binary, spawn_opts} = hd(opts)
      assert name == "web_api"
      assert binary == "/opt/bin/api_server"
      assert spawn_opts.ip == {10, 0, 0, 10}
      assert spawn_opts.ports == [{8080, 80}, {8443, 443}]
    end

    test "cache has limits and seccomp" do
      containers = FullExample.containers()
      cache = Enum.find(containers, &(&1.name == "cache"))
      assert cache.limits.cpu == 2
      assert cache.limits.memory == 512 * 1_048_576
      assert cache.seccomp.profile == :standard
    end

    test "write! creates valid term file" do
      path = Path.join(System.tmp_dir!(), "erlkoenig_full_#{:rand.uniform(100000)}.term")
      FullExample.write!(path)
      content = File.read!(path)
      assert content =~ "web_api"
      assert content =~ "worker"
      assert content =~ "redis"
      File.rm!(path)
    end
  end
end
