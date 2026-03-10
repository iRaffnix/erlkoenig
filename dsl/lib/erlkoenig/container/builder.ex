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

defmodule Erlkoenig.Container.Builder do
  @moduledoc """
  Pure functional builder for container definitions.

  Accumulates DSL calls into a map that serializes to an Erlang term
  compatible with `erlkoenig:spawn/2` SpawnOpts.
  """

  def new(name) when is_atom(name) do
    %{
      name: Atom.to_string(name),
      binary: nil,
      ip: nil,
      ports: [],
      args: [],
      env: %{},
      firewall: %{},
      limits: %{},
      seccomp: nil,
      restart: nil,
      files: %{},
      dns_name: nil,
      health_check: nil,
      zone: nil
    }
  end

  def set_binary(state, path) when is_binary(path) do
    %{state | binary: path}
  end

  def set_ip(state, {a, b, c, d} = ip)
      when is_integer(a) and a >= 0 and a <= 255
      when is_integer(b) and b >= 0 and b <= 255
      when is_integer(c) and c >= 0 and c <= 255
      when is_integer(d) and d >= 0 and d <= 255 do
    %{state | ip: ip}
  end

  def add_port(state, {host_port, ct_port})
      when is_integer(host_port) and host_port > 0 and host_port <= 65535
      when is_integer(ct_port) and ct_port > 0 and ct_port <= 65535 do
    %{state | ports: state.ports ++ [{host_port, ct_port}]}
  end

  def set_ports(state, ports) when is_list(ports) do
    %{state | ports: ports}
  end

  def set_args(state, args) when is_list(args) do
    %{state | args: Enum.map(args, &to_string/1)}
  end

  def set_env(state, env) when is_map(env) do
    normalized =
      Map.new(env, fn {k, v} -> {to_string(k), to_string(v)} end)

    %{state | env: Map.merge(state.env, normalized)}
  end

  def put_env(state, key, value) do
    %{state | env: Map.put(state.env, to_string(key), to_string(value))}
  end

  def set_firewall(state, term) when is_map(term) do
    %{state | firewall: term}
  end

  def set_firewall_profile(state, profile, opts \\ []) when is_atom(profile) do
    term = firewall_profile(profile, opts)
    %{state | firewall: term}
  end

  defp firewall_profile(:strict, opts) do
    allow_tcp = Keyword.get(opts, :allow_tcp, [])
    allow_udp = Keyword.get(opts, :allow_udp, [])

    rules =
      [:ct_established_accept, :icmp_accept] ++
        Enum.map(allow_tcp, &{:tcp_accept, &1}) ++
        Enum.map(allow_udp, &{:udp_accept, &1})

    %{chains: [%{name: "inbound", hook: :input, type: :filter, priority: 0, policy: :drop, rules: rules}]}
  end

  defp firewall_profile(:standard, opts) do
    allow_tcp = Keyword.get(opts, :allow_tcp, [])
    allow_udp = Keyword.get(opts, :allow_udp, [])

    rules =
      [:ct_established_accept, :icmp_accept, {:udp_accept, 53}] ++
        Enum.map(allow_tcp, &{:tcp_accept, &1}) ++
        Enum.map(allow_udp, &{:udp_accept, &1}) ++
        [:accept]

    %{chains: [%{name: "inbound", hook: :input, type: :filter, priority: 0, policy: :drop, rules: rules}]}
  end

  defp firewall_profile(:open, _opts) do
    %{chains: [%{name: "inbound", hook: :input, type: :filter, priority: 0, policy: :accept, rules: []}]}
  end

  def set_limits(state, limits) when is_map(limits) do
    %{state | limits: Map.merge(state.limits, limits)}
  end

  def set_restart(state, policy) do
    %{state | restart: policy}
  end

  def set_files(state, files) when is_map(files) do
    %{state | files: Map.merge(state.files, files)}
  end

  def add_file(state, path, content)
      when is_binary(path) and is_binary(content) do
    %{state | files: Map.put(state.files, path, content)}
  end

  def set_dns_name(state, name) when is_binary(name) do
    %{state | dns_name: name}
  end

  def set_zone(state, zone) when is_atom(zone) do
    %{state | zone: zone}
  end

  def set_health_check(state, opts) when is_list(opts) do
    %{state | health_check: Map.new(opts)}
  end

  def set_health_check(state, opts) when is_map(opts) do
    %{state | health_check: opts}
  end

  def to_spawn_opts(state) do
    opts = %{}
    opts = if state.ip, do: Map.put(opts, :ip, state.ip), else: opts
    opts = if state.ports != [], do: Map.put(opts, :ports, state.ports), else: opts
    opts = if state.args != [], do: Map.put(opts, :args, state.args), else: opts
    opts = if state.env != %{}, do: Map.put(opts, :env, state.env), else: opts
    opts = if state.firewall != %{}, do: Map.put(opts, :firewall, state.firewall), else: opts
    opts = if state.limits != %{}, do: Map.put(opts, :limits, state.limits), else: opts
    opts = if state.seccomp, do: Map.put(opts, :seccomp, state.seccomp), else: opts
    opts = if state.restart, do: Map.put(opts, :restart, state.restart), else: opts
    opts = if state.files != %{}, do: Map.put(opts, :files, state.files), else: opts
    opts = if state.health_check, do: Map.put(opts, :health_check, state.health_check), else: opts
    opts = if state.zone, do: Map.put(opts, :zone, state.zone), else: opts

    # DNS name: use explicit dns_name, or fall back to container definition name
    name = state.dns_name || state.name
    opts = if name, do: Map.put(opts, :name, name), else: opts

    opts
  end

  def to_term(state) do
    base = %{
      name: state.name,
      binary: state.binary
    }

    Map.merge(base, to_spawn_opts(state))
  end
end
