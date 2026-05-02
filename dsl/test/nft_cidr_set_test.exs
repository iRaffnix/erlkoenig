defmodule Erlkoenig.NftCidrSetTest do
  use ExUnit.Case, async: true

  alias Erlkoenig.Nft.TableBuilder

  # ============================================================
  # add_set now passes flags / elements through as map fields.
  # ============================================================

  describe "add_set flags pass-through" do
    test "single plain set stays two-tuple" do
      t = TableBuilder.new(:inet, "ct", owner: :host) |> TableBuilder.add_set("ban", :ipv4_addr)
      assert t.sets == [{"ban", :ipv4_addr}]
    end

    test "flags carry through to the set's opts map" do
      t =
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_set("ranges", :ipv4_addr, flags: [:interval])

      assert [{"ranges", :ipv4_addr, %{flags: [:interval]}}] = t.sets
    end

    test "elements carry through alongside flags" do
      t =
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_set("ranges", :ipv4_addr,
          flags: [:interval],
          elements: ["10.0.0.0/8"]
        )

      assert [{"ranges", :ipv4_addr, opts}] = t.sets
      assert opts.flags == [:interval]
      assert opts.elements == ["10.0.0.0/8"]
    end

    test "timeout integer carries through" do
      t =
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_set("ephemeral", :ipv4_addr,
          flags: [:timeout],
          timeout: 60_000
        )

      assert [{"ephemeral", :ipv4_addr, %{timeout: 60_000}}] = t.sets
    end
  end

  # ============================================================
  # add_cidr_set — compile-time validation + wiring.
  # ============================================================

  describe "add_cidr_set" do
    test "happy path: flags + elements populated" do
      t =
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_cidr_set(
          "trusted",
          ["10.0.0.0/8", "192.168.42.5"]
        )

      assert [{"trusted", :ipv4_addr, opts}] = t.sets
      assert opts.flags == [:interval]
      assert opts.elements == ["10.0.0.0/8", "192.168.42.5"]
    end

    test "accepts both CIDRs and bare IPs" do
      t =
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_cidr_set(
          "mixed",
          ["10.0.0.0/24", "203.0.113.1"]
        )

      assert [{"mixed", :ipv4_addr, %{elements: e}}] = t.sets
      assert e == ["10.0.0.0/24", "203.0.113.1"]
    end

    test "rejects empty list at compile time" do
      assert_raise CompileError, ~r/must not be empty/, fn ->
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_cidr_set("empty", [])
      end
    end

    test "rejects non-list second argument" do
      assert_raise CompileError, ~r/must be a list of strings/, fn ->
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_cidr_set("bad", "10.0.0.0/8")
      end
    end

    test "rejects non-binary entry" do
      assert_raise CompileError, ~r/each entry must be a string/, fn ->
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_cidr_set("bad", ["10.0.0.0/8", 42])
      end
    end

    test "rejects malformed CIDR string" do
      assert_raise CompileError, ~r/not a valid IPv4/, fn ->
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_cidr_set("bad", ["notanip"])
      end
    end

    test "rejects IPv6-ish string (we're IPv4-only for now)" do
      assert_raise CompileError, ~r/not a valid IPv4/, fn ->
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_cidr_set("bad", ["2001:db8::/32"])
      end
    end

    test "multiple cidr_sets coexist" do
      t =
        TableBuilder.new(:inet, "ct", owner: :host)
        |> TableBuilder.add_cidr_set("a", ["10.0.0.0/8"])
        |> TableBuilder.add_cidr_set("b", ["192.168.0.0/16"])

      assert length(t.sets) == 2
    end
  end

  # ============================================================
  # Full DSL pipeline: a stack module using nft_cidr_set emits a
  # set with flags + elements.
  # ============================================================

  defmodule StackWithCidrSet do
    use Erlkoenig.Stack

    host do
      ipvlan("demo", parent: {:dummy, "ek_demo"}, subnet: {10, 70, 0, 0, 24})

      nft_host do
        nft_cidr_set("trusted", [
          "10.70.0.0/24",
          "192.168.1.0/24",
          "203.0.113.42"
        ])

        base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
          nft_rule(:accept, ct_state: [:established, :related])
          nft_rule(:accept, set: "trusted")
        end
      end
    end

    pod "app", strategy: :one_for_one do
      container "web",
        binary: "/opt/bin/web",
        zone: "demo",
        replicas: 1,
        restart: :permanent do
        nft do
          input policy: :drop do
            nft_rule(:accept, ct_state: [:established, :related])
          end
        end
      end
    end
  end

  test "full DSL emits the cidr set in the host table term" do
    term = StackWithCidrSet.config()
    [host_table] = term.nft_tables

    assert Enum.any?(host_table.sets, fn
             {"trusted", :ipv4_addr, opts} ->
               opts.flags == [:interval] and
                 opts.elements == ["10.70.0.0/24", "192.168.1.0/24", "203.0.113.42"]

             _ ->
               false
           end)
  end
end
