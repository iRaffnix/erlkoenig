defmodule Erlkoenig.Ontology.Fact do
  @moduledoc """
  Closed-vocabulary fact emitted from validated Erlkoenig DSL builder state.
  """

  @type local_ref :: {atom(), term()}
  @type external_ref :: {:external, atom(), term()}
  @type ref :: local_ref() | external_ref()
  @type link :: {atom(), ref()}

  @type t :: %__MODULE__{
          ref: local_ref(),
          type: atom(),
          properties: map(),
          metadata: map() | nil,
          links: [link()],
          origin: Erlkoenig.Ontology.Origin.t() | nil
        }

  defstruct ref: nil,
            type: nil,
            properties: %{},
            metadata: nil,
            links: [],
            origin: nil
end
