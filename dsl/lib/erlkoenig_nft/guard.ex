#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0

defmodule ErlkoenigNft.Guard do
  @moduledoc """
  Guard outer wrapper for standalone use.

  Only provides the `guard do ... end` block. The inner macros
  (`detect`, `flood`, `respond`, `suspect`, `allowlist`, etc.)
  are defined in `Erlkoenig.Stack`.

  **Use `Erlkoenig.Stack` instead** — it includes everything.
  """

  alias ErlkoenigNft.Guard.Builder

  defmacro __using__(_opts) do
    quote do
      import ErlkoenigNft.Guard
      import Erlkoenig.TimeUnits
      Module.register_attribute(__MODULE__, :guard_builder, accumulate: false)
      @before_compile ErlkoenigNft.Guard
    end
  end

  defmacro __before_compile__(_env) do
    quote do
      def guard_config do
        if @guard_builder do
          Builder.to_term(@guard_builder)
        else
          nil
        end
      end
    end
  end

  defmacro guard(do: block) do
    quote do
      @guard_builder Builder.new()
      unquote(block)
    end
  end
end
