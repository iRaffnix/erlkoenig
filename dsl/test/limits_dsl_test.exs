defmodule Erlkoenig.LimitsDslTest do
  use ExUnit.Case, async: true

  defmodule LimitedCluster do
    use Erlkoenig.DSL

    container :web do
      binary "/opt/bin/server"
      ip {10, 0, 0, 10}
      limits cpu: 2, memory: "256M", pids: 100
      seccomp :standard
    end

    container :worker do
      binary "/opt/bin/worker"
      ip {10, 0, 0, 20}
      limits cpu: 4, memory: "1G", pps: 10_000, bps: "100M"
      seccomp :strict
    end

    container :minimal do
      binary "/opt/bin/minimal"
      ip {10, 0, 0, 30}
    end
  end

  describe "Limits in DSL" do
    test "web has limits and seccomp" do
      containers = LimitedCluster.containers()
      web = Enum.find(containers, &(&1.name == "web"))

      assert web.limits.cpu == 2
      assert web.limits.memory == 256 * 1_048_576
      assert web.limits.pids == 100
      assert web.seccomp.profile == :standard
    end

    test "worker has rate limits" do
      containers = LimitedCluster.containers()
      worker = Enum.find(containers, &(&1.name == "worker"))

      assert worker.limits.cpu == 4
      assert worker.limits.memory == 1_073_741_824
      assert worker.limits.pps == 10_000
      assert worker.limits.bps == 100 * 1_048_576
      assert worker.seccomp.profile == :strict
    end

    test "minimal has no limits or seccomp" do
      containers = LimitedCluster.containers()
      minimal = Enum.find(containers, &(&1.name == "minimal"))

      refute Map.has_key?(minimal, :limits)
      refute Map.has_key?(minimal, :seccomp)
    end

    test "spawn_opts includes limits" do
      opts_list = LimitedCluster.spawn_opts()
      {_, _, opts} = Enum.find(opts_list, fn {n, _, _} -> n == "web" end)
      assert opts.limits.cpu == 2
      assert opts.seccomp.profile == :standard
    end
  end
end
