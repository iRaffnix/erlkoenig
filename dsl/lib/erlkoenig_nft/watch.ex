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

defmodule ErlkoenigNft.Watch do
  @moduledoc """
  DSL macros for counter-based monitoring.

  ## Example

      defmodule MyMonitoring do
        use ErlkoenigNft.Watch

        watch :traffic do
          counter :ssh_pkts, :pps, threshold: 100
          counter :http_pkts, :pps, threshold: 5000
          counter :dropped, :packets, threshold: 1000
          interval 3000
          on_alert :log
          on_alert {:webhook, "https://alerts.internal/erlkoenig"}
        end
      end

      MyMonitoring.watches()   # => list of watch term maps
  """

  alias ErlkoenigNft.Watch.Builder

  defmacro __using__(_opts) do
    quote do
      import ErlkoenigNft.Watch
      Module.register_attribute(__MODULE__, :watch_builders, accumulate: true)
      Module.register_attribute(__MODULE__, :watch_current, accumulate: false)

      @before_compile ErlkoenigNft.Watch
    end
  end

  defmacro __before_compile__(_env) do
    quote do
      def watches do
        @watch_builders
        |> Enum.reverse()
        |> Enum.map(&Builder.to_term/1)
      end
    end
  end

  defmacro watch(name, do: block) do
    quote do
      @watch_current Builder.new(unquote(name))
      unquote(block)
      @watch_builders @watch_current
    end
  end

  defmacro counter(name, metric, opts) do
    quote do
      threshold = Keyword.fetch!(unquote(opts), :threshold)
      @watch_current Builder.add_counter(@watch_current, unquote(name))
      @watch_current Builder.add_threshold(@watch_current, unquote(name), unquote(metric), :>, threshold)
    end
  end

  defmacro interval(ms) do
    quote do: @watch_current Builder.set_interval(@watch_current, unquote(ms))
  end

  defmacro on_alert(action) do
    quote do: @watch_current Builder.add_action(@watch_current, unquote(action))
  end
end
