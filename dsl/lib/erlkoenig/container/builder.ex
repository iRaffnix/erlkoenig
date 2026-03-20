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
      caps: [],
      fw_rules: nil,
      fw_counters: [],
      fw_sets: [],
      guard: nil,
      watch: nil,
      observe: nil,
      policy: nil,
      restart: nil,
      volumes: [],
      files: %{},
      dns_name: nil,
      health_check: nil,
      zone: nil,
      signature: nil,
      rootfs: nil
    }
  end

  def set_binary(state, path) when is_binary(path) do
    %{state | binary: path}
  end

  def set_signature(state, :required), do: %{state | signature: :required}
  def set_signature(state, path) when is_binary(path), do: %{state | signature: path}

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

  # --- Firewall (inline nftables rules) ---

  def add_fw_rule(state, rule) do
    rules = (state.fw_rules || []) ++ [rule]
    %{state | fw_rules: rules}
  end

  def set_fw_counters(state, counters) when is_list(counters) do
    %{state | fw_counters: Enum.map(counters, &to_string/1)}
  end

  def add_fw_set(state, name, type) do
    %{state | fw_sets: state.fw_sets ++ [{to_string(name), type}]}
  end

  def set_guard(state, guard) when is_map(guard) do
    %{state | guard: guard}
  end

  def set_watch(state, watch) when is_map(watch) do
    %{state | watch: watch}
  end

  def set_observe(state, metrics) when is_list(metrics) do
    %{state | observe: metrics}
  end

  def set_policy(state, policy) when is_map(policy) do
    %{state | policy: policy}
  end

  def set_caps(state, caps) when is_list(caps) do
    %{state | caps: caps}
  end

  def set_limits(state, limits) when is_map(limits) do
    %{state | limits: Map.merge(state.limits, limits)}
  end

  def add_volume(state, vol) when is_map(vol) do
    %{state | volumes: state.volumes ++ [vol]}
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

  def set_rootfs(state, rootfs) when is_map(rootfs) do
    %{state | rootfs: rootfs}
  end

  def to_spawn_opts(state) do
    opts = %{}
    opts = if state.ip, do: Map.put(opts, :ip, state.ip), else: opts
    opts = if state.ports != [], do: Map.put(opts, :ports, state.ports), else: opts
    opts = if state.args != [], do: Map.put(opts, :args, state.args), else: opts
    opts = if state.env != %{}, do: Map.put(opts, :env, state.env), else: opts
    opts = if state.fw_rules do
      fw_term = %{
        chains: [%{
          name: "inbound",
          hook: :input,
          type: :filter,
          priority: 0,
          policy: :drop,
          rules: state.fw_rules
        }]
      }
      fw_term = if state.fw_counters != [], do: Map.put(fw_term, :counters, state.fw_counters), else: fw_term
      fw_term = if state.fw_sets != [], do: Map.put(fw_term, :sets, state.fw_sets), else: fw_term
      Map.put(opts, :firewall, fw_term)
    else
      opts
    end
    opts = if state.guard, do: Map.put(opts, :guard, state.guard), else: opts
    opts = if state.watch, do: Map.put(opts, :watch, state.watch), else: opts
    opts = if state.observe, do: Map.put(opts, :observe, state.observe), else: opts
    opts = if state.policy, do: Map.put(opts, :policy, state.policy), else: opts
    opts = if state.limits != %{}, do: Map.put(opts, :limits, state.limits), else: opts
    opts = if state.seccomp, do: Map.put(opts, :seccomp, state.seccomp), else: opts
    opts = if state.caps != [], do: Map.put(opts, :caps, state.caps), else: opts
    opts = if state.volumes != [], do: Map.put(opts, :volumes, state.volumes), else: opts
    opts = if state.restart, do: Map.put(opts, :restart, state.restart), else: opts
    opts = if state.files != %{}, do: Map.put(opts, :files, state.files), else: opts
    opts = if state.health_check, do: Map.put(opts, :health_check, state.health_check), else: opts
    opts = if state.zone, do: Map.put(opts, :zone, state.zone), else: opts
    opts = if state.rootfs, do: Map.put(opts, :rootfs, state.rootfs), else: opts

    opts = case state.signature do
      nil       -> opts
      :required -> Map.put(opts, :signature_required, true)
      path      -> Map.put(opts, :sig_path, path)
    end

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
