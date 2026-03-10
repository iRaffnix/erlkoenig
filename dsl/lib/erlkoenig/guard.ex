#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule Erlkoenig.Guard do
  @moduledoc """
  DSL macros for threat detection and automatic response.

  ## Example

      defmodule MyGuard do
        use Erlkoenig.Guard

        guard do
          detect :conn_flood, threshold: 50, window: 10
          detect :port_scan, threshold: 20, window: 60
          ban_duration 3600
          whitelist {10, 0, 0, 1}
        end
      end

      MyGuard.guard_config()   # => erlk_ct_guard compatible term
  """

  alias Erlkoenig.Guard.Builder

  defmacro __using__(_opts) do
    quote do
      import Erlkoenig.Guard
      Module.register_attribute(__MODULE__, :guard_builder, accumulate: false)

      @before_compile Erlkoenig.Guard
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

  defmacro detect(type, opts) do
    quote do
      threshold = Keyword.fetch!(unquote(opts), :threshold)
      window = Keyword.fetch!(unquote(opts), :window)
      @guard_builder Builder.add_detector(@guard_builder, unquote(type), threshold, window)
    end
  end

  defmacro ban_duration(seconds) do
    quote do: @guard_builder Builder.set_ban_duration(@guard_builder, unquote(seconds))
  end

  defmacro whitelist(ip) do
    quote do: @guard_builder Builder.add_whitelist(@guard_builder, unquote(ip))
  end

  defmacro cleanup_interval(ms) do
    quote do: @guard_builder Builder.set_cleanup_interval(@guard_builder, unquote(ms))
  end
end
