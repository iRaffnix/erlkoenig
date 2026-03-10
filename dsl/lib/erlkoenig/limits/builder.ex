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

defmodule Erlkoenig.Limits.Builder do
  @moduledoc """
  Pure functional builder for container resource limits.

  Produces Erlang terms for cgroup-based resource control.
  """

  def new do
    %{}
  end

  def set_cpu(limits, count) when is_integer(count) and count > 0 do
    Map.put(limits, :cpu, count)
  end

  def set_memory(limits, bytes) when is_integer(bytes) and bytes > 0 do
    Map.put(limits, :memory, bytes)
  end

  def set_memory(limits, str) when is_binary(str) do
    Map.put(limits, :memory, parse_bytes(str))
  end

  def set_pids(limits, max) when is_integer(max) and max > 0 do
    Map.put(limits, :pids, max)
  end

  def set_pps(limits, rate) when is_integer(rate) and rate > 0 do
    Map.put(limits, :pps, rate)
  end

  def set_bps(limits, bytes) when is_integer(bytes) and bytes > 0 do
    Map.put(limits, :bps, bytes)
  end

  def set_bps(limits, str) when is_binary(str) do
    Map.put(limits, :bps, parse_bytes(str))
  end

  def set_io_weight(limits, weight) when is_integer(weight) and weight >= 1 and weight <= 10000 do
    Map.put(limits, :io_weight, weight)
  end

  def to_term(limits), do: limits

  # --- Byte parsing ---

  @doc false
  def parse_bytes(str) when is_binary(str) do
    str = String.trim(str)

    cond do
      String.ends_with?(str, "G") ->
        parse_number(String.trim_trailing(str, "G")) * 1_073_741_824

      String.ends_with?(str, "M") ->
        parse_number(String.trim_trailing(str, "M")) * 1_048_576

      String.ends_with?(str, "K") ->
        parse_number(String.trim_trailing(str, "K")) * 1024

      true ->
        parse_number(str)
    end
  end

  defp parse_number(str) do
    case Integer.parse(str) do
      {n, ""} -> n
      _ -> raise ArgumentError, "invalid byte value: #{inspect(str)}"
    end
  end
end
