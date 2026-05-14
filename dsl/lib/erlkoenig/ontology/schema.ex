defmodule Erlkoenig.Ontology.Schema do
  @moduledoc """
  Closed vocabulary for Erlkoenig ontology facts and relations.
  """

  alias Erlkoenig.Ontology.Fact

  @fact_types [
    :stack,
    :host,
    :interface,
    :zone,
    :pod,
    :container,
    :capability,
    :volume,
    :publish,
    :stream,
    :nft_table,
    :nft_chain,
    :nft_rule,
    :nft_counter,
    :nft_set,
    :nft_map,
    :nft_vmap,
    :nft_flowtable,
    :nflog_group,
    :guard,
    :watch,
    :admission_denial,
    :resource_request,
    :capacity_snapshot,
    :resource_holder
  ]

  @relations [
    :has_host,
    :has_interface,
    :has_zone,
    :has_pod,
    :has_container,
    :runs_in_zone,
    :requires_capability,
    :mounts_volume,
    :publishes_metric,
    :streams_channel,
    :has_nft_table,
    :owns_nft_table,
    :has_chain,
    :has_rule,
    :uses_counter,
    :uses_set,
    :uses_map,
    :uses_vmap,
    :uses_flowtable,
    :logs_to_nflog_group,
    :performs_action,
    :jumps_to_chain,
    :has_guard,
    :has_watch,
    :watches_counter,
    :has_resource_request,
    :rejected_by_snapshot,
    :capacity_held_by
  ]

  @type t :: %__MODULE__{
          fact_types: [atom()],
          relations: [atom()]
        }

  defstruct fact_types: @fact_types,
            relations: @relations

  @spec default() :: t()
  def default, do: %__MODULE__{}

  @spec fact_types() :: [atom()]
  def fact_types, do: @fact_types

  @spec relations() :: [atom()]
  def relations, do: @relations

  @spec assert_known!(t(), Fact.t()) :: :ok | no_return()
  def assert_known!(%__MODULE__{} = schema, %Fact{} = fact) do
    unless fact.type in schema.fact_types do
      raise ArgumentError, "unknown ontology fact type #{inspect(fact.type)}"
    end

    Enum.each(fact.links, fn
      {relation, _ref} ->
        unless relation in schema.relations do
          raise ArgumentError, "unknown ontology relation #{inspect(relation)}"
        end

      other ->
        raise ArgumentError, "malformed ontology link #{inspect(other)}"
    end)

    :ok
  end
end
