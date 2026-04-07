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
      honeypot_ports: [],
      honeypot_ban_duration: 86400,
      escalation: [3600, 21600, 86400, 604800],
      whitelist: [{127, 0, 0, 1}],
      cleanup_interval: 30_000
    }
  end

  def add_detector(state, type, threshold, window)
      when type in [:conn_flood, :port_scan, :slow_scan] and
           is_integer(threshold) and is_integer(window) do
    %{state | detectors: state.detectors ++ [{type, threshold, window}]}
  end

  def set_ban_duration(state, seconds) when is_integer(seconds) and seconds > 0 do
    %{state | ban_duration: seconds}
  end

  def set_honeypot_ports(state, ports) when is_list(ports) do
    %{state | honeypot_ports: ports}
  end

  def set_honeypot_ban_duration(state, seconds) when is_integer(seconds) and seconds > 0 do
    %{state | honeypot_ban_duration: seconds}
  end

  def set_escalation(state, durations) when is_list(durations) do
    %{state | escalation: durations}
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

    base = if state.honeypot_ports != [] do
      base
      |> Map.put(:honeypot_ports, state.honeypot_ports)
      |> Map.put(:honeypot_ban_duration, state.honeypot_ban_duration)
    else
      base
    end

    base = if state.escalation != [3600, 21600, 86400, 604800] do
      Map.put(base, :escalation, state.escalation)
    else
      base
    end

    Enum.reduce(state.detectors, base, fn
      {type, threshold, window}, acc ->
        Map.put(acc, type, {threshold, window})
    end)
  end
end
