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

defmodule Erlkoenig.Watch.Builder do
  @moduledoc """
  Pure functional builder for counter-based monitoring configs.

  Produces terms compatible with `erlkoenig_nft_watch:start_link/1`.
  """

  def new(name) when is_atom(name) or is_binary(name) do
    %{
      name: to_string(name),
      family: 1,
      table: "erlkoenig_ct",
      counters: [],
      interval: 2000,
      thresholds: [],
      actions: []
    }
  end

  def set_interval(state, ms) when is_integer(ms) and ms > 0 do
    %{state | interval: ms}
  end

  def set_table(state, family, table) do
    %{state | family: family, table: to_string(table)}
  end

  def add_counter(state, name) do
    %{state | counters: state.counters ++ [to_string(name)]}
  end

  def add_counters(state, names) when is_list(names) do
    %{state | counters: state.counters ++ Enum.map(names, &to_string/1)}
  end

  def add_threshold(state, counter, metric, op, value) when metric in [:pps, :bps, :packets, :bytes] and op in [:>, :<, :>=, :<=, :==] do
    t = %{counter: to_string(counter), metric: metric, op: op, value: value}
    %{state | thresholds: state.thresholds ++ [t]}
  end

  def add_action(state, :log) do
    %{state | actions: state.actions ++ [:log]}
  end

  def add_action(state, {:webhook, url}) when is_binary(url) do
    %{state | actions: state.actions ++ [{:webhook, url}]}
  end

  def add_action(state, {:exec, cmd}) when is_binary(cmd) do
    %{state | actions: state.actions ++ [{:exec, cmd}]}
  end

  def add_action(state, :isolate) do
    %{state | actions: state.actions ++ [:isolate]}
  end

  def to_term(state) do
    base = %{
      family: state.family,
      table: state.table,
      counters: state.counters,
      interval: state.interval
    }

    base = if state.thresholds != [], do: Map.put(base, :thresholds, thresholds_to_term(state.thresholds)), else: base
    base = if state.actions != [], do: Map.put(base, :actions, state.actions), else: base
    Map.put(base, :name, state.name)
  end

  defp thresholds_to_term(thresholds) do
    Enum.map(thresholds, fn %{counter: c, metric: m, op: op, value: v} ->
      {c, c, m, op, v}
    end)
  end
end
