defmodule Erlkoenig.Ontology.Origin do
  @moduledoc """
  Source location carried by ontology facts when origin retention is enabled.
  """

  @type t :: %__MODULE__{
          file: String.t() | nil,
          line: non_neg_integer() | nil,
          context: atom() | nil
        }

  defstruct file: nil, line: nil, context: nil

  @spec from_caller(Macro.Env.t(), atom()) :: t()
  def from_caller(%Macro.Env{} = caller, context) when is_atom(context) do
    %__MODULE__{file: caller.file, line: caller.line, context: context}
  end
end
