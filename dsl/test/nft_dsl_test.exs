#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0
#
defmodule Erlkoenig.Nft.DslTest do
  @moduledoc """
  Tests for the Elixir-side nft DSL builders.

  Two surfaces:

  * `Erlkoenig.Nft.TableBuilder` — table accumulator with compile-time
    validators that prevent classic traps the runtime can only fail at
    load-time: empty chains, duplicate chain names, undeclared counter
    refs, vmap entries that jump to chains that don't exist.
  * `Erlkoenig.Nft.ChainBuilder` — base/regular chain construction
    with strict whitelists for hook / type / priority / policy /
    action, plus the `conn_limit per_ip: N` sugar.

  We poke the validators from both ends: happy path passes silently,
  every documented error case raises `CompileError` with a message
  that mentions the violation. Tests favour small focused cases over
  integration scenarios so a failure tells the operator exactly which
  rule tripped.
  """

  use ExUnit.Case, async: true

  alias Erlkoenig.Nft.ChainBuilder
  alias Erlkoenig.Nft.TableBuilder

  # ------------------------------------------------------------------
  # TableBuilder — basic accumulation
  # ------------------------------------------------------------------

  describe "TableBuilder.new/2" do
    test "creates inet-family table with given name" do
      t = TableBuilder.new(:inet, "t_test")
      assert t.family == :inet
      assert t.name == "t_test"
      assert t.counters == []
      assert t.chains == []
      assert t.sets == []
      assert t.maps == []
      assert t.vmaps == []
      assert t.flowtables == []
    end

    test "respects family override" do
      t = TableBuilder.new(:ip, "t4")
      assert t.family == :ip
    end
  end

  describe "TableBuilder.add_counter/2" do
    test "appends counter names preserving order" do
      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_counter("c1")
        |> TableBuilder.add_counter("c2")
        |> TableBuilder.add_counter("c3")

      assert t.counters == ["c1", "c2", "c3"]
    end
  end

  # ------------------------------------------------------------------
  # TableBuilder.add_set — meta filtering
  # ------------------------------------------------------------------

  describe "TableBuilder.add_set/4" do
    test "name+type only produces 2-tuple (no meta map)" do
      t = TableBuilder.new(:inet, "t") |> TableBuilder.add_set("s", :ipv4_addr)
      assert t.sets == [{"s", :ipv4_addr}]
    end

    test "flags: [...] gets folded into meta" do
      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_set("s", :ipv4_addr, flags: [:interval])

      assert t.sets == [{"s", :ipv4_addr, %{flags: [:interval]}}]
    end

    test "timeout: integer gets folded in" do
      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_set("s", :inet_service, timeout: 600)

      assert t.sets == [{"s", :inet_service, %{timeout: 600}}]
    end

    test "non-integer timeout is silently ignored" do
      # put_if_integer drops anything that isn't an integer. Document
      # the soft-filter: an operator writing `timeout: "10m"` gets a
      # set without timeout, not a compile error. Pin the behaviour
      # so a future tightening is a deliberate decision.
      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_set("s", :inet_service, timeout: "not-an-int")

      assert t.sets == [{"s", :inet_service}]
    end

    test "non-list flags is silently ignored" do
      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_set("s", :ipv4_addr, flags: :interval)

      assert t.sets == [{"s", :ipv4_addr}]
    end

    test "unknown option is ignored, not carried into meta" do
      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_set("s", :ipv4_addr, foobar: true)

      assert t.sets == [{"s", :ipv4_addr}]
    end
  end

  # ------------------------------------------------------------------
  # TableBuilder.add_cidr_set — validation
  # ------------------------------------------------------------------

  describe "TableBuilder.add_cidr_set/3" do
    test "happy path with CIDR strings" do
      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_cidr_set("allowed", ["10.0.0.0/8", "192.168.1.1"])

      assert [{"allowed", :ipv4_addr, meta}] = t.sets
      assert meta.flags == [:interval]
      assert meta.elements == ["10.0.0.0/8", "192.168.1.1"]
    end

    test "rejects empty list (would match nothing silently)" do
      assert_raise CompileError, ~r/must not be empty/, fn ->
        TableBuilder.new(:inet, "t") |> TableBuilder.add_cidr_set("allowed", [])
      end
    end

    test "rejects non-string element" do
      assert_raise CompileError, ~r/each entry must be a string/, fn ->
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_cidr_set("allowed", ["10.0.0.1", {10, 0, 0, 2}])
      end
    end

    test "rejects malformed CIDR" do
      assert_raise CompileError, ~r/is not a valid IPv4 CIDR/, fn ->
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_cidr_set("allowed", ["not-an-ip"])
      end
    end

    test "rejects non-list second arg" do
      assert_raise CompileError, ~r/must be a list/, fn ->
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_cidr_set("allowed", "10.0.0.0/8")
      end
    end
  end

  # ------------------------------------------------------------------
  # TableBuilder.normalize_map_entries — shape dispatch
  # ------------------------------------------------------------------

  describe "TableBuilder.normalize_map_entries/1" do
    test "replica_ips tuple passes through untouched" do
      ref = {:replica_ips, "backend", "api"}
      assert TableBuilder.normalize_map_entries(ref) == ref
    end

    test "empty list is preserved" do
      assert TableBuilder.normalize_map_entries([]) == []
    end

    test "keyword list with :entries unpacks inner list" do
      entries = [{<<10, 0, 0, 1>>, :accept}, {<<10, 0, 0, 2>>, :drop}]
      assert TableBuilder.normalize_map_entries(entries: entries) == entries
    end

    test "keyword list without :entries yields empty" do
      # Keyword.get(list, :entries, []) returns []. Documented behaviour
      # — pinned here so any future tightening (e.g. raise on empty kw)
      # is a deliberate change.
      assert TableBuilder.normalize_map_entries(other: 1) == []
    end

    test "positional list of 2-tuples passes through" do
      list = [{1, :a}, {2, :b}, {3, :c}]
      assert TableBuilder.normalize_map_entries(list) == list
    end

    test "non-list non-tuple raises CompileError" do
      assert_raise CompileError, ~r/unexpected shape/, fn ->
        TableBuilder.normalize_map_entries(%{k: :v})
      end
    end

    test "mixed list with non-tuple entry raises CompileError" do
      # Not a keyword (has non-atom entry) AND not pure 2-tuples —
      # the dispatch must reject rather than silently keep the list.
      assert_raise CompileError, ~r/keyword list|positional list|unexpected shape/, fn ->
        TableBuilder.normalize_map_entries([{:a, 1}, :bare_atom, {:b, 2}])
      end
    end
  end

  # ------------------------------------------------------------------
  # TableBuilder.add_flowtable — required devices
  # ------------------------------------------------------------------

  describe "TableBuilder.add_flowtable/3" do
    test "records name, devices and default priority" do
      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_flowtable("ft", devices: ["eth0", "eth1"])

      assert [%{name: "ft", hook: :ingress, priority: 0, devices: ["eth0", "eth1"]}] =
               t.flowtables
    end

    test "custom priority overrides default" do
      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_flowtable("ft", devices: ["eth0"], priority: -100)

      assert [%{priority: -100}] = t.flowtables
    end

    test "rejects missing devices" do
      assert_raise CompileError, ~r/at least one interface/, fn ->
        TableBuilder.new(:inet, "t") |> TableBuilder.add_flowtable("ft", [])
      end
    end

    test "rejects explicit empty devices" do
      assert_raise CompileError, ~r/at least one interface/, fn ->
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_flowtable("ft", devices: [])
      end
    end
  end

  # ------------------------------------------------------------------
  # TableBuilder.validate! — the load-bearing compile-time guard
  # ------------------------------------------------------------------

  describe "TableBuilder.validate!/1" do
    test "rejects table with zero chains" do
      t = TableBuilder.new(:inet, "t")

      assert_raise CompileError, ~r/must have at least one chain/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "rejects duplicate chain names" do
      c1 = ChainBuilder.new_base("same", hook: :input, type: :filter, priority: 0, policy: :drop)
      c2 = ChainBuilder.new_base("same", hook: :output, type: :filter, priority: 0, policy: :accept)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(c1)
        |> TableBuilder.add_chain(c2)

      assert_raise CompileError, ~r/duplicate chain names/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "rejects rule referencing undeclared counter" do
      c =
        ChainBuilder.new_base("input",
          hook: :input, type: :filter, priority: 0, policy: :drop
        )
        |> ChainBuilder.add_rule(:accept, counter: "unknown_ctr")

      t = TableBuilder.new(:inet, "t") |> TableBuilder.add_chain(c)

      assert_raise CompileError, ~r/counter "unknown_ctr" referenced but not declared/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "accepts rule referencing declared counter" do
      c =
        ChainBuilder.new_base("input",
          hook: :input, type: :filter, priority: 0, policy: :drop
        )
        |> ChainBuilder.add_rule(:accept, counter: "ok_ctr")

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_counter("ok_ctr")
        |> TableBuilder.add_chain(c)

      assert :ok = TableBuilder.validate!(t)
    end

    test "rejects vmap :jump to undeclared chain" do
      # Regression guard for the bug that made tutorial 03 fail with
      # cryptic ENOENT: a vmap element referenced a chain that was
      # never created, the kernel rejected the whole atomic batch.
      # Caught now at compile time with a loud pointer at the offender.
      c = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(c)
        |> TableBuilder.add_vmap("dispatch", :ipv4_addr, [
          {<<10, 0, 0, 1>>, {:jump, "never_declared"}}
        ])

      assert_raise CompileError, ~r/jumping to chain "never_declared"/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "rejects vmap :goto to undeclared chain" do
      c = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(c)
        |> TableBuilder.add_vmap("dispatch", :ipv4_addr, [
          {<<10, 0, 0, 1>>, {:goto, "missing"}}
        ])

      assert_raise CompileError, ~r/goto chain "missing" which is not declared/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "accepts vmap :jump to declared chain" do
      input = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)
      target = ChainBuilder.new_regular("target")

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(input)
        |> TableBuilder.add_chain(target)
        |> TableBuilder.add_vmap("dispatch", :ipv4_addr, [
          {<<10, 0, 0, 1>>, {:jump, "target"}}
        ])

      assert :ok = TableBuilder.validate!(t)
    end

    test "rejects duplicate set names" do
      # Two NEWSET with the same name in one atomic batch → kernel EEXIST
      # and rollback of the entire transaction. Catch at compile time
      # with a pointer at the offender.
      c = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(c)
        |> TableBuilder.add_set("dup", :ipv4_addr)
        |> TableBuilder.add_set("dup", :inet_service)

      assert_raise CompileError, ~r/duplicate set names.*"dup"/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "rejects duplicate map names" do
      c = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(c)
        |> TableBuilder.add_map("dup", :ipv4_addr, :verdict, [])
        |> TableBuilder.add_map("dup", :ipv4_addr, :mark, [])

      assert_raise CompileError, ~r/duplicate map names.*"dup"/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "rejects duplicate vmap names" do
      c = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(c)
        |> TableBuilder.add_vmap("dup", :ipv4_addr, [])
        |> TableBuilder.add_vmap("dup", :ipv4_addr, [])

      assert_raise CompileError, ~r/duplicate vmap names.*"dup"/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "rejects duplicate flowtable names" do
      c = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(c)
        |> TableBuilder.add_flowtable("dup", devices: ["eth0"])
        |> TableBuilder.add_flowtable("dup", devices: ["eth1"])

      assert_raise CompileError, ~r/duplicate flowtable names.*"dup"/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "rejects duplicate counter names" do
      c = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(c)
        |> TableBuilder.add_counter("dup")
        |> TableBuilder.add_counter("dup")

      assert_raise CompileError, ~r/duplicate counter names.*"dup"/, fn ->
        TableBuilder.validate!(t)
      end
    end

    test "ignores vmap entries that aren't jump/goto" do
      # A verdict-only entry like `{key, :accept}` is legal — the
      # validator only needs to chase chain references, not every
      # possible verdict. Plain verdicts should not trip it.
      input = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(input)
        |> TableBuilder.add_vmap("dispatch", :ipv4_addr, [
          {<<10, 0, 0, 1>>, :accept}
        ])

      assert :ok = TableBuilder.validate!(t)
    end
  end

  # ------------------------------------------------------------------
  # TableBuilder.to_term — shape of the emitted term
  # ------------------------------------------------------------------

  describe "TableBuilder.to_term/1" do
    test "minimal table emits family, name, counters, chains only" do
      c = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)
      t = TableBuilder.new(:inet, "t") |> TableBuilder.add_chain(c)
      term = TableBuilder.to_term(t)

      assert term.family == :inet
      assert term.name == "t"
      assert term.counters == []
      assert is_list(term.chains)
      # Absent features stay out of the map — not nil.
      refute Map.has_key?(term, :sets)
      refute Map.has_key?(term, :maps)
      refute Map.has_key?(term, :vmaps)
      refute Map.has_key?(term, :flowtables)
    end

    test "sets / maps / vmaps / flowtables surface when populated" do
      c = ChainBuilder.new_base("input", hook: :input, type: :filter, priority: 0, policy: :drop)

      t =
        TableBuilder.new(:inet, "t")
        |> TableBuilder.add_chain(c)
        |> TableBuilder.add_set("s", :ipv4_addr)
        |> TableBuilder.add_map("m", :ipv4_addr, :verdict, [])
        |> TableBuilder.add_vmap("v", :ipv4_addr, [])
        |> TableBuilder.add_flowtable("ft", devices: ["eth0"])

      term = TableBuilder.to_term(t)

      assert term.sets != nil
      assert term.maps != nil
      assert term.vmaps != nil
      assert term.flowtables != nil
    end
  end

  # ------------------------------------------------------------------
  # ChainBuilder.new_base — whitelist enforcement
  # ------------------------------------------------------------------

  describe "ChainBuilder.new_base/2" do
    test "accepts valid hook/type/priority/policy" do
      c =
        ChainBuilder.new_base("input",
          hook: :input, type: :filter, priority: :filter, policy: :drop
        )

      assert c.name == "input"
      assert c.type == :base
      assert c.hook == :input
      assert c.chain_type == :filter
      assert c.priority == :filter
      assert c.policy == :drop
    end

    test "accepts integer priority (netfilter numeric value)" do
      c =
        ChainBuilder.new_base("input",
          hook: :input, type: :filter, priority: -200, policy: :accept
        )

      assert c.priority == -200
    end

    test "rejects invalid hook" do
      assert_raise CompileError, ~r/invalid hook/, fn ->
        ChainBuilder.new_base("c",
          hook: :ingress_typo, type: :filter, priority: 0, policy: :drop
        )
      end
    end

    test "rejects invalid type" do
      assert_raise CompileError, ~r/invalid type/, fn ->
        ChainBuilder.new_base("c", hook: :input, type: :foo, priority: 0, policy: :drop)
      end
    end

    test "rejects non-integer non-atom priority" do
      assert_raise CompileError, ~r/invalid priority/, fn ->
        ChainBuilder.new_base("c",
          hook: :input, type: :filter, priority: "high", policy: :drop
        )
      end
    end

    test "rejects invalid policy" do
      assert_raise CompileError, ~r/invalid policy/, fn ->
        ChainBuilder.new_base("c",
          hook: :input, type: :filter, priority: 0, policy: :queue
        )
      end
    end
  end

  # ------------------------------------------------------------------
  # ChainBuilder.add_rule — action whitelist + :jump requires :to
  # ------------------------------------------------------------------

  describe "ChainBuilder.add_rule/3" do
    test "appends rule with empty opts becoming an empty map" do
      c =
        ChainBuilder.new_base("c", hook: :input, type: :filter, priority: 0, policy: :drop)
        |> ChainBuilder.add_rule(:accept, [])

      assert c.rules == [{:accept, %{}}]
    end

    test "converts keyword opts to map" do
      c =
        ChainBuilder.new_base("c", hook: :input, type: :filter, priority: 0, policy: :drop)
        |> ChainBuilder.add_rule(:accept, tcp_dport: 80, counter: "web")

      assert [{:accept, opts}] = c.rules
      assert opts == %{tcp_dport: 80, counter: "web"}
    end

    test "rejects unknown action" do
      c = ChainBuilder.new_base("c", hook: :input, type: :filter, priority: 0, policy: :drop)

      assert_raise CompileError, ~r/invalid action/, fn ->
        ChainBuilder.add_rule(c, :allow_maybe, [])
      end
    end

    test "rejects :jump without :to" do
      c = ChainBuilder.new_base("c", hook: :input, type: :filter, priority: 0, policy: :drop)

      assert_raise CompileError, ~r/:jump requires :to/, fn ->
        ChainBuilder.add_rule(c, :jump, [])
      end
    end

    test "accepts :jump with :to" do
      c =
        ChainBuilder.new_base("c", hook: :input, type: :filter, priority: 0, policy: :drop)
        |> ChainBuilder.add_rule(:jump, to: "target")

      assert [{:jump, %{to: "target"}}] = c.rules
    end
  end

  # ------------------------------------------------------------------
  # ChainBuilder.add_conn_limit — sugar + strict reject on deprecated
  # ------------------------------------------------------------------

  describe "ChainBuilder.compile_conn_limit!/1 + add_conn_limit/2" do
    test "per_ip: N expands to {:connlimit_drop, max: N}" do
      assert {:connlimit_drop, [max: 42]} =
               ChainBuilder.compile_conn_limit!(per_ip: 42)
    end

    test "per_ip as sugar adds correct rule to chain" do
      c =
        ChainBuilder.new_base("c", hook: :input, type: :filter, priority: 0, policy: :drop)
        |> ChainBuilder.add_conn_limit(per_ip: 50)

      assert [{:connlimit_drop, %{max: 50}}] = c.rules
    end

    test "rejects missing :per_ip" do
      assert_raise CompileError, ~r/needs :per_ip/, fn ->
        ChainBuilder.compile_conn_limit!([])
      end
    end

    test "rejects :per_ip zero" do
      assert_raise CompileError, ~r/positive integer/, fn ->
        ChainBuilder.compile_conn_limit!(per_ip: 0)
      end
    end

    test "rejects :per_ip negative" do
      assert_raise CompileError, ~r/positive integer/, fn ->
        ChainBuilder.compile_conn_limit!(per_ip: -5)
      end
    end

    test "rejects :per_ip non-integer" do
      assert_raise CompileError, ~r/positive integer/, fn ->
        ChainBuilder.compile_conn_limit!(per_ip: "ten")
      end
    end

    test "rejects deprecated :global option" do
      assert_raise CompileError, ~r/option removed/, fn ->
        ChainBuilder.compile_conn_limit!(per_ip: 10, global: 100)
      end
    end

    test "rejects deprecated :audit option" do
      assert_raise CompileError, ~r/option removed/, fn ->
        ChainBuilder.compile_conn_limit!(per_ip: 10, audit: true)
      end
    end
  end
end
