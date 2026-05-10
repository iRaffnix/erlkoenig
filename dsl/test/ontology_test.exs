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
