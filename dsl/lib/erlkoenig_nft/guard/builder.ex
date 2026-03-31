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

defmodule ErlkoenigNft.Guard.Builder do
  @moduledoc """
  Pure functional builder for threat detection configs.

  Produces terms compatible with `erlkoenig_nft_ct_guard:start_link/1`.
  """

  def new do
    %{
      detectors: [],
      ban_duration: 3600,
      whitelist: [{127, 0, 0, 1}],
      cleanup_interval: 30_000
    }
  end

  def add_detector(state, :conn_flood, threshold, window)
      when is_integer(threshold) and is_integer(window) do
    %{state | detectors: state.detectors ++ [{:conn_flood, threshold, window}]}
  end

  def add_detector(state, :port_scan, threshold, window)
      when is_integer(threshold) and is_integer(window) do
    %{state | detectors: state.detectors ++ [{:port_scan, threshold, window}]}
  end

  def set_ban_duration(state, seconds) when is_integer(seconds) and seconds > 0 do
    %{state | ban_duration: seconds}
  end

  def add_whitelist(state, ip) when is_tuple(ip) do
    %{state | whitelist: state.whitelist ++ [ip]}
  end

  def set_cleanup_interval(state, ms) when is_integer(ms) and ms > 0 do
    %{state | cleanup_interval: ms}
  end

  def to_term(state) do
    base = %{
      ban_duration: state.ban_duration,
      whitelist: state.whitelist,
      cleanup_interval: state.cleanup_interval
    }

    Enum.reduce(state.detectors, base, fn
      {:conn_flood, threshold, window}, acc ->
        Map.put(acc, :conn_flood, {threshold, window})

      {:port_scan, threshold, window}, acc ->
        Map.put(acc, :port_scan, {threshold, window})
    end)
  end
end
