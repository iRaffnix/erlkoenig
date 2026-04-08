defmodule ErlkoenigNft.GuardTest do
  use ExUnit.Case, async: true

  alias ErlkoenigNft.Guard.Builder

  describe "Guard.Builder" do
    test "new creates defaults" do
      b = Builder.new()
      assert b.ban_duration == 3600
      assert b.allowlist == [{127, 0, 0, 1}]
      assert b.cleanup_interval == 30_000
      assert b.detectors == []
      assert b.suspect_after == 3
      assert b.probation == 120
      assert b.forget_after == 300
    end

    test "add_flood" do
      b = Builder.new() |> Builder.add_flood(50, 10)
      assert b.detectors == [{:conn_flood, 50, 10}]
    end

    test "add_port_scan" do
      b = Builder.new() |> Builder.add_port_scan(20, 60)
      assert b.detectors == [{:port_scan, 20, 60}]
    end

    test "add_slow_scan" do
      b = Builder.new() |> Builder.add_slow_scan(5, 3600)
      assert b.detectors == [{:slow_scan, 5, 3600}]
    end

    test "set_suspect" do
      b = Builder.new() |> Builder.set_suspect(5, :ports)
      assert b.suspect_after == 5
      assert b.suspect_by == :ports
    end

    test "set_probation" do
      b = Builder.new() |> Builder.set_probation(300)
      assert b.probation == 300
    end

    test "set_forget_after" do
      b = Builder.new() |> Builder.set_forget_after(600)
      assert b.forget_after == 600
    end

    test "set_allowlist" do
      b = Builder.new() |> Builder.set_allowlist([{10, 0, 0, 1}, {10, 0, 0, 2}])
      assert {10, 0, 0, 1} in b.allowlist
      assert {127, 0, 0, 1} in b.allowlist
    end

    test "to_term compiles to ct_guard format" do
      term =
        Builder.new()
        |> Builder.add_flood(50, 10)
        |> Builder.add_port_scan(20, 60)
        |> Builder.add_slow_scan(5, 3600)
        |> Builder.set_ban_duration(1800)
        |> Builder.set_honeypot_ban_duration(86400)
        |> Builder.set_honeypot_ports([22, 23])
        |> Builder.set_escalation([3600, 21600])
        |> Builder.set_suspect(3, :ports)
        |> Builder.set_probation(120)
        |> Builder.set_forget_after(300)
        |> Builder.set_allowlist([{10, 0, 0, 1}])
        |> Builder.to_term()

      assert term.conn_flood == {50, 10}
      assert term.port_scan == {20, 60}
      assert term.slow_scan == {5, 3600}
      assert term.ban_duration == 1800
      assert term.honeypot_ban_duration == 86400
      assert term.honeypot_ports == [22, 23]
      assert term.escalation == [3600, 21600]
      assert term.suspect_after == 3
      assert term.suspect_by == :ports
      assert term.probation == 120
      assert term.forget_after == 300
      assert {127, 0, 0, 1} in term.whitelist
      assert {10, 0, 0, 1} in term.whitelist
    end
  end

  # --- DSL macro tests (via Erlkoenig.Stack) ---

  describe "three_tier example compiles guard" do
    test "guard block produces correct config" do
      [{mod, _}] = Code.compile_file("../examples/three_tier_nft.exs")
      config = mod.config()

      guard = config.ct_guard
      assert guard.conn_flood == {50, 10}
      assert guard.port_scan == {20, 60}
      assert guard.slow_scan == {5, 3600}
      assert guard.ban_duration == 3600
      assert guard.honeypot_ban_duration == 86400
      assert guard.escalation == [3600, 21600, 86400, 604800]
      assert guard.suspect_after == 3
      assert guard.probation == 120
      assert guard.forget_after == 300
      assert {127, 0, 0, 1} in guard.whitelist
      assert {10, 0, 0, 1} in guard.whitelist
    end
  end
end
