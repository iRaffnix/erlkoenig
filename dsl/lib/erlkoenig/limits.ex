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

defmodule Erlkoenig.Limits do
  @moduledoc """
  DSL macros for container resource limits.

  ## Example (inside a container block)

      container :web do
        binary "/opt/bin/server"
        ip {10, 0, 0, 10}
        limits cpu: 2, memory: "256M", pids: 100
      end

  ## Standalone usage

      defmodule MyLimits do
        alias Erlkoenig.Limits.Builder
        def web_limits do
          Builder.new()
          |> Builder.set_cpu(2)
          |> Builder.set_memory("256M")
          |> Builder.set_pids(100)
          |> Builder.to_term()
        end
      end

  ## Supported keys

  - `cpu` — Number of CPU cores
  - `memory` — Bytes (integer) or string ("256M", "1G", "512K")
  - `pids` — Max process count
  - `pps` — Packets per second (nf_tables rate limit)
  - `bps` — Bytes per second (integer or string "100M")
  - `io_weight` — IO weight (1-10000)
  """

  alias Erlkoenig.Limits.Builder

  @doc "Build a limits term from a keyword list."
  def build(opts) when is_list(opts) do
    Enum.reduce(opts, Builder.new(), fn
      {:cpu, v}, acc -> Builder.set_cpu(acc, v)
      {:memory, v}, acc when is_integer(v) -> Builder.set_memory(acc, v)
      {:memory, v}, acc when is_binary(v) -> Builder.set_memory(acc, v)
      {:pids, v}, acc -> Builder.set_pids(acc, v)
      {:pps, v}, acc -> Builder.set_pps(acc, v)
      {:bps, v}, acc when is_integer(v) -> Builder.set_bps(acc, v)
      {:bps, v}, acc when is_binary(v) -> Builder.set_bps(acc, v)
      {:io_weight, v}, acc -> Builder.set_io_weight(acc, v)
    end)
    |> Builder.to_term()
  end
end
