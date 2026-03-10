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

defmodule Erlkoenig.Firewall.Builder do
  @moduledoc """
  Pure functional builder for firewall configurations.

  Accumulates DSL calls into a map that can be serialized to an
  Erlang term compatible with `erlkoenig_firewall_nft:add_container/5`.
  """

  # --- Constructor ---

  def new(name \\ "default") when is_binary(name) do
    %{name: name, sets: [], counters: [], chains: [], rules_acc: []}
  end

  # --- Sets ---

  def add_set(state, name, type) when is_binary(name) and type in [:ipv4_addr, :ipv6_addr] do
    update_in(state, [:sets], &(&1 ++ [{name, type}]))
  end

  def add_set(state, name, type, opts) when is_binary(name) and type in [:ipv4_addr, :ipv6_addr] do
    timeout = Keyword.fetch!(opts, :timeout)
    update_in(state, [:sets], &(&1 ++ [{name, type, %{flags: [:timeout], timeout: timeout}}]))
  end

  # --- Counters ---

  def add_counters(state, names) when is_list(names) do
    %{state | counters: state.counters ++ Enum.map(names, &to_string/1)}
  end

  # --- Chains ---

  def add_chain(state, name, opts, rules) when is_binary(name) and is_list(rules) do
    chain = %{
      name: name,
      hook: Keyword.fetch!(opts, :hook),
      type: Keyword.get(opts, :type, :filter),
      priority: Keyword.get(opts, :priority, 0),
      policy: Keyword.fetch!(opts, :policy),
      rules: rules
    }

    update_in(state, [:chains], &(&1 ++ [chain]))
  end

  # --- Rule constructors ---

  def ct_established_accept, do: :ct_established_accept
  def icmp_accept, do: :icmp_accept
  def accept, do: :accept

  def tcp_accept(port) when is_integer(port), do: {:tcp_accept, port}

  def tcp_accept(port, opts) when is_integer(port) and is_list(opts) do
    counter = Keyword.get(opts, :counter)
    limit = Keyword.get(opts, :limit)
    build_tcp_accept(port, counter, limit)
  end

  defp build_tcp_accept(port, nil, nil), do: {:tcp_accept, port}
  defp build_tcp_accept(port, counter, nil), do: {:tcp_accept, port, to_string(counter)}

  defp build_tcp_accept(port, counter, {rate, burst_opts}) do
    burst = if is_list(burst_opts), do: Keyword.fetch!(burst_opts, :burst), else: burst_opts
    c = if counter, do: to_string(counter), else: "tcp_#{port}"
    {:tcp_accept_limited, port, c, %{rate: rate, burst: burst}}
  end

  def tcp_port_range_accept(from, to_port), do: {:tcp_port_range_accept, from, to_port}
  def tcp_reject(port), do: {:tcp_reject, port}

  def udp_accept(port) when is_integer(port), do: {:udp_accept, port}

  def udp_accept(port, opts) when is_integer(port) and is_list(opts) do
    case Keyword.get(opts, :counter) do
      nil -> {:udp_accept, port}
      counter -> {:udp_accept, port, to_string(counter)}
    end
  end

  def udp_port_range_accept(from, to_port), do: {:udp_port_range_accept, from, to_port}

  def protocol_accept(proto), do: {:protocol_accept, proto}

  def ip_saddr_accept(ip), do: {:ip_saddr_accept, ip}
  def ip_saddr_drop(ip), do: {:ip_saddr_drop, ip}

  def iifname_accept(name), do: {:iifname_accept, name}

  def set_lookup_drop(set_name), do: {:set_lookup_drop, set_name}
  def set_lookup_drop(set_name, counter), do: {:set_lookup_drop, set_name, to_string(counter)}

  def connlimit_drop(max), do: {:connlimit_drop, max, 0}
  def connlimit_drop(max, offset), do: {:connlimit_drop, max, offset}

  def log_drop(prefix), do: {:log_drop, prefix}
  def log_drop(prefix, counter), do: {:log_drop, prefix, to_string(counter)}

  def log_reject(prefix), do: {:log_reject, prefix}

  def dnat(ip, port), do: {:dnat, ip, port}

  # --- Rule accumulator (used by chain macro) ---

  def push_rule(state, rule) do
    update_in(state, [:rules_acc], &(&1 ++ [rule]))
  end

  def take_rules(state) do
    {state.rules_acc, %{state | rules_acc: []}}
  end

  # --- Serialization ---

  def to_term(state) do
    base = %{
      chains: Enum.map(state.chains, &chain_to_term/1)
    }

    base = if state.sets != [], do: Map.put(base, :sets, state.sets), else: base
    base = if state.counters != [], do: Map.put(base, :counters, state.counters), else: base
    base
  end

  def write!(state, path) do
    term = to_term(state)
    formatted = :io_lib.format(~c"~tp.~n", [term])
    File.write!(path, formatted)
  end

  defp chain_to_term(chain) do
    %{
      name: chain.name,
      hook: chain.hook,
      type: chain.type,
      priority: chain.priority,
      policy: chain.policy,
      rules: chain.rules
    }
  end
end
