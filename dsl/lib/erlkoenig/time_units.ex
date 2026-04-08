#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0

defmodule Erlkoenig.TimeUnits do
  @moduledoc """
  Time unit macros for readable DSL durations.

      flood over: 50, within: s(10)
      ban_for h(1)
      escalate [h(1), h(6), h(24), d(7)]
      forget_after m(5)

  Each macro expands to seconds at compile time.
  """

  @doc "Seconds (identity)."
  defmacro s(n), do: n

  @doc "Minutes → seconds."
  defmacro m(n), do: quote(do: unquote(n) * 60)

  @doc "Hours → seconds."
  defmacro h(n), do: quote(do: unquote(n) * 3600)

  @doc "Days → seconds."
  defmacro d(n), do: quote(do: unquote(n) * 86400)
end
