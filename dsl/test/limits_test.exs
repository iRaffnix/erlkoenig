defmodule Erlkoenig.LimitsTest do
  use ExUnit.Case, async: true

  alias Erlkoenig.Limits
  alias Erlkoenig.Limits.Builder

  describe "Builder" do
    test "set_cpu" do
      l = Builder.new() |> Builder.set_cpu(4)
      assert l.cpu == 4
    end

    test "set_memory with integer" do
      l = Builder.new() |> Builder.set_memory(268_435_456)
      assert l.memory == 268_435_456
    end

    test "set_memory with string M" do
      l = Builder.new() |> Builder.set_memory("256M")
      assert l.memory == 256 * 1_048_576
    end

    test "set_memory with string G" do
      l = Builder.new() |> Builder.set_memory("1G")
      assert l.memory == 1_073_741_824
    end

    test "set_memory with string K" do
      l = Builder.new() |> Builder.set_memory("512K")
      assert l.memory == 512 * 1024
    end

    test "set_pids" do
      l = Builder.new() |> Builder.set_pids(100)
      assert l.pids == 100
    end

    test "set_pps" do
      l = Builder.new() |> Builder.set_pps(10_000)
      assert l.pps == 10_000
    end

    test "set_bps with string" do
      l = Builder.new() |> Builder.set_bps("100M")
      assert l.bps == 100 * 1_048_576
    end

    test "set_io_weight" do
      l = Builder.new() |> Builder.set_io_weight(500)
      assert l.io_weight == 500
    end

    test "parse_bytes raises on invalid" do
      assert_raise ArgumentError, fn ->
        Builder.parse_bytes("abc")
      end
    end
  end

  describe "Limits.build/1" do
    test "builds from keyword list" do
      term = Limits.build(cpu: 2, memory: "256M", pids: 50)
      assert term.cpu == 2
      assert term.memory == 256 * 1_048_576
      assert term.pids == 50
    end

    test "builds with all options" do
      term = Limits.build(cpu: 4, memory: "1G", pids: 200, pps: 10_000, bps: "100M", io_weight: 500)
      assert term.cpu == 4
      assert term.memory == 1_073_741_824
      assert term.pids == 200
      assert term.pps == 10_000
      assert term.bps == 100 * 1_048_576
      assert term.io_weight == 500
    end
  end

  describe "Seccomp" do
    test ":strict has minimal syscalls" do
      profile = Erlkoenig.Seccomp.get(:strict)
      assert profile.profile == :strict
      assert :read in profile.syscalls
      assert :write in profile.syscalls
      refute :socket in profile.syscalls
    end

    test ":standard has network syscalls" do
      profile = Erlkoenig.Seccomp.get(:standard)
      assert profile.profile == :standard
      assert :socket in profile.syscalls
      assert :connect in profile.syscalls
      assert :accept in profile.syscalls
    end

    test ":permissive blocks dangerous syscalls" do
      profile = Erlkoenig.Seccomp.get(:permissive)
      assert profile.profile == :permissive
      assert :ptrace in profile.blocked
      assert :mount in profile.blocked
      assert :bpf in profile.blocked
    end

    test "list returns all profiles" do
      assert Erlkoenig.Seccomp.list() == [:strict, :standard, :permissive]
    end
  end
end
