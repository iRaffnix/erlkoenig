#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0

defmodule Erlkoenig.Validation do
  @moduledoc "Shared compile-time validation helpers for DSL builders."

  @doc "Raise CompileError if items have duplicate values for the given field."
  def check_uniqueness(items, field, context) do
    names = Enum.map(items, &Map.get(&1, field))
    dupes = names -- Enum.uniq(names)
    if dupes != [] do
      raise CompileError, description: "duplicate #{context}: #{inspect(Enum.uniq(dupes))}"
    end
  end
end
