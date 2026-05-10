defmodule Erlkoenig.Ontology.EmitContext do
  @moduledoc """
  Explicit context passed through builder fact emission.
  """

  @type local_ref :: {atom(), term()}
  @type external_ref :: {:external, atom(), term()}
  @type ref :: local_ref() | external_ref()

  @type t :: %__MODULE__{
          parent_ref: local_ref() | nil,
          vocabulary: Erlkoenig.Ontology.Schema.t(),
          origin_resolver: (term() -> Erlkoenig.Ontology.Origin.t() | nil),
          id_namespace: term()
        }

  defstruct parent_ref: nil,
            vocabulary: Erlkoenig.Ontology.Schema.default(),
            origin_resolver: &Erlkoenig.Ontology.EmitContext.default_origin_resolver/1,
            id_namespace: nil

  @spec default_origin_resolver(term()) :: nil
  def default_origin_resolver(_), do: nil

  @spec child(t(), local_ref(), term()) :: t()
  def child(%__MODULE__{} = context, parent_ref, id_namespace) do
    %{context | parent_ref: parent_ref, id_namespace: id_namespace}
  end
end
