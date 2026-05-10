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

  defstruct cpu: nil,
            memory: nil,
            pids: nil,
            pps: nil,
            bps: nil,
            io_weight: nil

  @type t :: %__MODULE__{
          cpu: pos_integer() | nil,
          memory: pos_integer() | nil,
          pids: pos_integer() | nil,
          pps: pos_integer() | nil,
          bps: pos_integer() | nil,
          io_weight: pos_integer() | nil
        }

  @spec new() :: t()
  def new do
    %__MODULE__{}
  end

  @spec set_cpu(t(), pos_integer()) :: t()
  def set_cpu(limits, count) when is_integer(count) and count > 0 do
    %{limits | cpu: count}
  end

  @spec set_memory(t(), pos_integer() | String.t()) :: t()
  def set_memory(limits, bytes) when is_integer(bytes) and bytes > 0 do
    %{limits | memory: bytes}
  end

  def set_memory(limits, str) when is_binary(str) do
    %{limits | memory: parse_bytes(str)}
  end

  @spec set_pids(t(), pos_integer()) :: t()
  def set_pids(limits, max) when is_integer(max) and max > 0 do
    %{limits | pids: max}
  end

  @spec set_pps(t(), pos_integer()) :: t()
  def set_pps(limits, rate) when is_integer(rate) and rate > 0 do
    %{limits | pps: rate}
  end

  @spec set_bps(t(), pos_integer() | String.t()) :: t()
  def set_bps(limits, bytes) when is_integer(bytes) and bytes > 0 do
    %{limits | bps: bytes}
  end

  def set_bps(limits, str) when is_binary(str) do
    %{limits | bps: parse_bytes(str)}
  end

  @spec set_io_weight(t(), pos_integer()) :: t()
  def set_io_weight(limits, weight) when is_integer(weight) and weight >= 1 and weight <= 10000 do
    %{limits | io_weight: weight}
  end

  @spec validate!(t()) :: t()
  def validate!(%__MODULE__{} = limits), do: limits

  @spec to_term(t()) :: map()
  def to_term(%__MODULE__{} = limits) do
    limits
    |> Map.from_struct()
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

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
