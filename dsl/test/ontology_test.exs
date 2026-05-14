defmodule Erlkoenig.OntologyTest do
  use ExUnit.Case

  alias Erlkoenig.Ontology.{Fact, Schema, World}

  test "empty stack exposes a validated ontology world" do
    [{mod, _}] =
      Code.compile_string(~S"""
      defmodule TestOntology.EmptyStack do
        use Erlkoenig.Stack
      end
      """)

    assert %World{} = world = mod.ontology()
    assert Enum.map(world.facts, & &1.type) == [:stack]
    assert [%Fact{ref: {:stack, "TestOntology.EmptyStack"}}] = world.facts
  end

  test "stack fact carries compile origin" do
    [{mod, _}] =
      Code.compile_string(
        ~S"""
        defmodule TestOntology.OriginStack do
          use Erlkoenig.Stack
        end
        """,
        "origin_stack.exs"
      )

    [%Fact{origin: origin}] = mod.ontology().facts

    assert %Erlkoenig.Ontology.Origin{file: "origin_stack.exs", context: :stack} = origin
    assert is_integer(origin.line)
  end

  test "schema rejects unknown fact types" do
    fact = %Fact{ref: {:bogus, "x"}, type: :bogus}

    assert_raise ArgumentError, ~r/unknown ontology fact type :bogus/, fn ->
      Schema.assert_known!(Schema.default(), fact)
    end
  end

  test "world rejects links to missing local refs" do
    fact = %Fact{
      ref: {:container, "app"},
      type: :container,
      links: [{:runs_in_zone, {:zone, "missing"}}]
    }

    assert_raise ArgumentError, ~r/links to missing local ref/, fn ->
      World.new([fact])
    end
  end

  test "three_tier_ipvlan_fw emits deterministic builder-driven fact counts" do
    mod = compile_three_tier!()

    world = apply(mod, :ontology, [])
    counts = Enum.frequencies_by(world.facts, & &1.type)

    assert counts.stack == 1
    assert counts.host == 1
    assert counts.interface == 1
    assert counts.zone == 1
    assert counts.pod == 1
    assert counts.container == 3
    assert counts.capability == 3
    assert counts.publish == 3
    assert counts.stream == 1
    assert counts.guard == 1
    assert counts.nft_table == 2
    assert counts.nft_chain == 9
    assert counts.nft_rule == 37
    assert counts.nft_counter == 3
    assert counts.nft_set == 1
    assert counts.nflog_group == 2
    assert length(world.facts) == 70
  end

  test "three_tier_ipvlan_fw ontology output order is deterministic" do
    mod = compile_three_tier!()

    first = Enum.map(apply(mod, :ontology, []).facts, & &1.ref)
    second = Enum.map(apply(mod, :ontology, []).facts, & &1.ref)

    assert first == second
  end

  test "three_tier_ipvlan_fw ontology matches golden snapshot" do
    mod = compile_three_tier!()

    actual =
      mod
      |> apply(:ontology, [])
      |> snapshot_facts()

    fixture =
      "test/fixtures/three_tier_world.term"
      |> File.read!()
      |> Code.eval_string()
      |> elem(0)

    assert actual == fixture.facts

    assert snapshot_hash(actual) == fixture.sha256
  end

  test "admission denial compiler emits causal capacity world" do
    world =
      Erlkoenig.Ontology.Compiler.from_admission_denial(%{
        container_id: "api-2",
        limits: %{memory: 4_294_967_296, pids: 512},
        reason: %{
          reason: :insufficient_memory,
          required: 4_294_967_296,
          available: 2_147_483_648,
          evidence: %{
            kind: :memory,
            ceiling: 8_589_934_592,
            allocated: 5_368_709_120,
            committed: 1_073_741_824,
            last_updated: 1_778_486_220_000,
            allocated_sources: [
              %{id: "api-0", name: "api", kind: :memory, value: 2_147_483_648},
              %{id: "worker-0", name: "worker", kind: :memory, value: 3_221_225_472}
            ],
            committed_sources: [
              %{id: "api-1", kind: :memory, value: 1_073_741_824, since_ms: 1_778_486_219_100}
            ]
          }
        }
      })

    assert %World{} = world
    counts = Enum.frequencies_by(world.facts, & &1.type)

    assert counts.admission_denial == 1
    assert counts.resource_request == 2
    assert counts.capacity_snapshot == 1
    assert counts.resource_holder == 3

    denial = find_fact!(world, {:admission_denial, "api-2/denial"})
    assert denial.properties.reason == :insufficient_memory
    assert denial.properties.required == 4_294_967_296
    assert denial.properties.available == 2_147_483_648

    snapshot = find_fact!(world, {:capacity_snapshot, "api-2/snapshot"})
    assert snapshot.properties.ceiling == 8_589_934_592
    assert snapshot.links == [{:rejected_by_snapshot, {:admission_denial, "api-2/denial"}}]

    committed_holder = find_fact!(world, {:resource_holder, "api-2/committed-memory-api-1-0"})
    assert committed_holder.properties.class == :committed
    assert committed_holder.properties.since_ms == 1_778_486_219_100
    assert committed_holder.links == [{:capacity_held_by, {:capacity_snapshot, "api-2/snapshot"}}]
  end

  test "from_emit_event consumes the AMQP wire shape from erlkoenig_error:to_map/1" do
    # Source-of-truth: this map MUST match what `erlkoenig_error:to_map/1`
    # produces after JSON round-trip. If the Erlang side changes the
    # shape (key names, nesting, value coercion) update this fixture
    # in lockstep — `ek admission denial <id> --format json` emits this
    # exact shape into stdin of `mix erlkoenig.explain admission`.
    #
    # Properties of the round-trip:
    #   * map keys are binary strings  (json:decode default)
    #   * atom values were stringified  (jsonable_map in to_map)
    #   * nested maps preserved
    #   * lists preserved
    event = %{
      "type" => "ct",
      "reason" => "resource_admission_denied",
      "code" => "EK_CT_RESOURCE_ADMISSION_DENIED",
      "context" => "resource admission denied",
      "data" => %{
        "zone" => "zone_a",
        "reason" => %{
          "reason" => "insufficient_memory",
          "required" => 4_294_967_296,
          "available" => 2_147_483_648,
          "evidence" => %{
            "kind" => "memory",
            "ceiling" => 8_589_934_592,
            "allocated" => 5_368_709_120,
            "committed" => 1_073_741_824,
            "last_updated" => 1_778_486_220_000,
            "allocated_sources" => [
              %{"id" => "api-0", "name" => "api", "kind" => "memory",
                "value" => 2_147_483_648},
              %{"id" => "worker-0", "name" => "worker", "kind" => "memory",
                "value" => 3_221_225_472}
            ],
            "committed_sources" => [
              %{"id" => "api-1", "kind" => "memory",
                "value" => 1_073_741_824, "since_ms" => 1_778_486_219_100}
            ]
          }
        },
        "limits" => %{"memory" => 4_294_967_296, "pids" => 512}
      },
      "severity" => "error",
      "source" => %{},
      "ts_ms" => 1_778_486_220_000,
      "container" => "api-2"
    }

    world = Erlkoenig.Ontology.Compiler.from_emit_event(event)
    assert %World{} = world

    counts = Enum.frequencies_by(world.facts, & &1.type)
    assert counts.admission_denial == 1
    assert counts.resource_request == 2
    assert counts.capacity_snapshot == 1
    assert counts.resource_holder == 3

    # Container id and limits flow through.
    denial = find_fact!(world, {:admission_denial, "api-2/denial"})
    assert denial.properties.container_id == "api-2"
    assert denial.properties.required == 4_294_967_296
    assert denial.properties.available == 2_147_483_648

    # Snapshot is correctly linked back to the denial.
    snapshot = find_fact!(world, {:capacity_snapshot, "api-2/snapshot"})
    assert snapshot.properties.ceiling == 8_589_934_592
    assert snapshot.links == [{:rejected_by_snapshot, {:admission_denial, "api-2/denial"}}]

    # The committed source's since_ms is preserved end-to-end — that's
    # the field added in node_resources for P3-style "who holds capacity
    # since when" explanations.
    committed_holder =
      find_fact!(world, {:resource_holder, "api-2/committed-memory-api-1-0"})

    assert committed_holder.properties.class == :committed
    assert committed_holder.properties.since_ms == 1_778_486_219_100
    assert committed_holder.properties.value == 1_073_741_824

    # Two allocated sources land as separate holder facts.
    allocated_holders =
      Enum.filter(world.facts, fn f ->
        f.type == :resource_holder and f.properties[:class] == :allocated
      end)

    assert length(allocated_holders) == 2

    assert Enum.sort(Enum.map(allocated_holders, & &1.properties.holder_id)) ==
             ["api-0", "worker-0"]
  end

  test "from_emit_event rejects unknown event shapes loudly" do
    # Wrong type — not a resource-admission denial.
    other = %{
      "type" => "ct",
      "reason" => "spawn_timeout",
      "data" => %{},
      "container" => "x"
    }

    assert {:error, {:unknown_event_shape, ^other}} =
             Erlkoenig.Ontology.Compiler.from_emit_event(other)

    # Wrong type field entirely.
    bad = %{"foo" => "bar"}
    assert {:error, {:unknown_event_shape, ^bad}} =
             Erlkoenig.Ontology.Compiler.from_emit_event(bad)
  end

  defp compile_three_tier! do
    :code.purge(ThreeTierIpvlanFw)
    :code.delete(ThreeTierIpvlanFw)

    [{mod, _}] = Code.compile_file("../examples/stacks/three_tier_ipvlan_fw.exs")
    mod
  end

  defp snapshot_facts(world) do
    world.facts
    |> Enum.map(fn fact ->
      %{fact | origin: nil}
    end)
    |> Enum.sort_by(& &1.ref)
  end

  defp snapshot_hash(facts) do
    facts
    |> canonical()
    |> :erlang.term_to_binary()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp find_fact!(world, ref) do
    Enum.find(world.facts, &(&1.ref == ref)) || flunk("missing ontology fact #{inspect(ref)}")
  end

  defp canonical(%Fact{} = fact) do
    {:fact, fact.ref, fact.type, canonical(fact.properties), canonical(fact.metadata),
     canonical(fact.links), canonical(fact.origin)}
  end

  defp canonical(%Erlkoenig.Ontology.Origin{} = origin) do
    {:origin, origin.file, origin.line, origin.context}
  end

  defp canonical(map) when is_map(map) do
    map
    |> Enum.map(fn {key, value} -> {key, canonical(value)} end)
    |> Enum.sort_by(fn {key, _value} -> inspect(key) end)
  end

  defp canonical(list) when is_list(list), do: Enum.map(list, &canonical/1)

  defp canonical(tuple) when is_tuple(tuple) do
    tuple
    |> Tuple.to_list()
    |> Enum.map(&canonical/1)
    |> List.to_tuple()
  end

  defp canonical(value), do: value
end
