defmodule Erlkoenig.Ontology.World do
  @moduledoc """
  Validated set of ontology facts for one Erlkoenig stack.
  """

  alias Erlkoenig.Ontology.{Fact, Schema}

  @type t :: %__MODULE__{
          schema: Schema.t(),
          facts: [Fact.t()]
        }

  defstruct schema: Schema.default(), facts: []

  @spec new([Fact.t()], Schema.t()) :: t()
  def new(facts, schema \\ Schema.default()) when is_list(facts) do
    world = %__MODULE__{schema: schema, facts: facts}
    validate!(world)
  end

  @spec validate!(t()) :: t()
  def validate!(%__MODULE__{} = world) do
    Enum.each(world.facts, &Schema.assert_known!(world.schema, &1))

    refs = Enum.map(world.facts, & &1.ref)
    duplicate_refs = refs -- Enum.uniq(refs)

    if duplicate_refs != [] do
      raise ArgumentError, "duplicate ontology refs #{inspect(Enum.uniq(duplicate_refs))}"
    end

    local_refs = MapSet.new(refs)

    Enum.each(world.facts, fn fact ->
      Enum.each(fact.links, fn {_relation, ref} ->
        validate_ref!(ref, local_refs, fact)
      end)
    end)

    world
  end

  defp validate_ref!({:external, type, _id}, _local_refs, _fact) when is_atom(type), do: :ok

  defp validate_ref!({type, _id} = ref, local_refs, fact) when is_atom(type) do
    unless MapSet.member?(local_refs, ref) do
      raise ArgumentError,
            "ontology fact #{inspect(fact.ref)} links to missing local ref #{inspect(ref)}"
    end
  end

  defp validate_ref!(ref, _local_refs, fact) do
    raise ArgumentError,
          "ontology fact #{inspect(fact.ref)} has malformed ref #{inspect(ref)}"
  end
end
