defmodule Erlkoenig.GuardTest do
  use ExUnit.Case, async: true

  alias Erlkoenig.Guard.Builder

  describe "Guard.Builder" do
    test "new creates defaults" do
      b = Builder.new()
      assert b.ban_duration == 3600
      assert b.whitelist == [{127, 0, 0, 1}]
      assert b.cleanup_interval == 30_000
      assert b.detectors == []
    end

    test "add_detector conn_flood" do
      b = Builder.new() |> Builder.add_detector(:conn_flood, 50, 10)
      assert b.detectors == [{:conn_flood, 50, 10}]
    end

    test "add_detector port_scan" do
      b = Builder.new() |> Builder.add_detector(:port_scan, 20, 60)
      assert b.detectors == [{:port_scan, 20, 60}]
    end

    test "set_ban_duration" do
      b = Builder.new() |> Builder.set_ban_duration(7200)
      assert b.ban_duration == 7200
    end

    test "add_whitelist" do
      b = Builder.new() |> Builder.add_whitelist({10, 0, 0, 1})
      assert {10, 0, 0, 1} in b.whitelist
      assert {127, 0, 0, 1} in b.whitelist
    end

    test "to_term matches erlk_ct_guard format" do
      term =
        Builder.new()
        |> Builder.add_detector(:conn_flood, 50, 10)
        |> Builder.add_detector(:port_scan, 20, 60)
        |> Builder.set_ban_duration(1800)
        |> Builder.add_whitelist({10, 0, 0, 1})
        |> Builder.to_term()

      assert term.conn_flood == {50, 10}
      assert term.port_scan == {20, 60}
      assert term.ban_duration == 1800
      assert {127, 0, 0, 1} in term.whitelist
      assert {10, 0, 0, 1} in term.whitelist
      assert term.cleanup_interval == 30_000
    end
  end

  # --- DSL tests ---

  defmodule FullGuard do
    use Erlkoenig.Guard

    guard do
      detect :conn_flood, threshold: 50, window: 10
      detect :port_scan, threshold: 15, window: 30
      ban_duration 7200
      whitelist {10, 0, 0, 1}
      whitelist {192, 168, 1, 1}
      cleanup_interval 60_000
    end
  end

  defmodule MinimalGuard do
    use Erlkoenig.Guard

    guard do
      detect :conn_flood, threshold: 100, window: 5
    end
  end

  describe "Guard DSL" do
    test "FullGuard has all detectors" do
      config = FullGuard.guard_config()
      assert config.conn_flood == {50, 10}
      assert config.port_scan == {15, 30}
    end

    test "FullGuard has custom ban and whitelist" do
      config = FullGuard.guard_config()
      assert config.ban_duration == 7200
      assert {10, 0, 0, 1} in config.whitelist
      assert {192, 168, 1, 1} in config.whitelist
      assert config.cleanup_interval == 60_000
    end

    test "MinimalGuard uses defaults for missing" do
      config = MinimalGuard.guard_config()
      assert config.conn_flood == {100, 5}
      refute Map.has_key?(config, :port_scan)
      assert config.ban_duration == 3600
    end
  end
end
