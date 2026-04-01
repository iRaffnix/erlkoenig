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

defmodule Erlkoenig.Zone.Builder do
  @moduledoc """
  Accumulates zone definitions — network segment with explicit
  firewall chains, pod deployments, and BPF steering rules.

  A zone has NO implicit network access. Without chain/rule
  definitions, the zone is completely isolated from the host,
  internet, and other zones. Every network path must be
  explicitly declared.

  ## Structure

      zone "production", subnet: {10, 0, 0, 0} do
        chain "forward", policy: :drop do
          rule :accept, ct: :established
          rule :accept, udp: 53, oif: "ek_br_production"
          rule :masquerade, oif: "eth0"
          rule :drop
        end

        deploy "webstack", replicas: 10

        steer {178, 104, 16, 107}, port: 443, proto: :tcp,
          backends: ["webstack.frontend"]
      end
  """

  defstruct name: nil,
            subnet: {10, 0, 0, 0},
            gateway: nil,
            netmask: 24,
            bridge: nil,
            pool_start: nil,
            pool_end: nil,
            interface: nil,
            chains: [],
            rules_acc: [],
            deployments: [],
            steers: [],
            containers: [],
            current_ct: nil

  def new(name, opts) do
    subnet = Keyword.get(opts, :subnet, {10, 0, 0, 0})
    {sa, sb, sc, _} = subnet

    {pool_start, pool_end} = case Keyword.get(opts, :pool) do
      {first, last} when is_tuple(first) and is_tuple(last) -> {first, last}
      nil -> {{sa, sb, sc, 2}, {sa, sb, sc, 254}}
    end

    %__MODULE__{
      name: to_string(name),
      subnet: subnet,
      gateway: Keyword.get(opts, :gateway, {sa, sb, sc, 1}),
      netmask: Keyword.get(opts, :netmask, 24),
      bridge: Keyword.get(opts, :bridge) && to_string(Keyword.get(opts, :bridge))
              || "ek_br_#{name}",
      pool_start: pool_start,
      pool_end: pool_end,
      interface: Keyword.get(opts, :interface) && to_string(Keyword.get(opts, :interface))
    }
  end

  # --- Chain/Rule (zone-level firewall) ---

  def begin_chain(%__MODULE__{} = z, _name, _opts) do
    %{z | rules_acc: []}
  end

  def end_chain(%__MODULE__{} = z, name, opts) do
    chain = build_chain(name, opts, z.rules_acc)
    %{z | chains: z.chains ++ [chain], rules_acc: []}
  end

  def push_rule(%__MODULE__{} = z, rule) do
    %{z | rules_acc: z.rules_acc ++ [rule]}
  end

  defp build_chain(name, opts, rules) do
    base = %{name: name, rules: rules}
    base = if opts[:hook], do: Map.put(base, :hook, opts[:hook]), else: base
    base = if opts[:type], do: Map.put(base, :type, opts[:type]), else: base
    base = if opts[:priority], do: Map.put(base, :priority, opts[:priority]), else: base
    base = if opts[:policy], do: Map.put(base, :policy, opts[:policy]), else: base
    base
  end

  # --- Deployments ---

  def add_deployment(%__MODULE__{deployments: deps} = z, pod_name, replicas)
      when is_binary(pod_name) and is_integer(replicas) and replicas > 0 do
    %{z | deployments: deps ++ [{pod_name, replicas}]}
  end

  # --- Steering ---

  def add_steer(%__MODULE__{steers: steers} = z, vip, opts) do
    steer = %{
      vip: vip,
      port: Keyword.fetch!(opts, :port),
      proto: Keyword.fetch!(opts, :proto),
      backends: Keyword.fetch!(opts, :backends)
    }
    %{z | steers: steers ++ [steer]}
  end

  # --- Standalone containers (without pod) ---

  def begin_container(%__MODULE__{} = z, name, opts) do
    ct = %{
      name: to_string(name),
      image: opts[:image] && to_string(opts[:image]),
      binary: opts[:binary] && to_string(opts[:binary]),
      ip: opts[:ip],
      ports: opts[:ports] || [],
      limits: opts[:limits] || %{},
      restart: opts[:restart] || :no_restart,
      seccomp: opts[:seccomp] || :default,
      uid: opts[:uid] || 65534,
      gid: opts[:gid] || 65534,
      args: opts[:args] || [],
      caps: opts[:caps] || [],
      chains: [],
      rules_acc: [],
      env: [],
      files: %{},
      volumes: [],
      health_check: nil,
      firewall: nil
    }
    %{z | current_ct: ct}
  end

  def end_container(%__MODULE__{current_ct: ct, containers: cts} = z) do
    ct = if ct.chains != [] do
      %{ct | firewall: %{chains: ct.chains}}
    else
      ct
    end
    %{z | containers: cts ++ [ct], current_ct: nil}
  end

  # --- Term output ---

  def to_term(%__MODULE__{} = z) do
    zone_term = %{
      name: z.name,
      subnet: z.subnet,
      gateway: z.gateway,
      netmask: z.netmask,
      bridge: z.bridge,
      pool: %{start: z.pool_start, stop: z.pool_end}
    }

    zone_term = if z.interface,
      do: Map.put(zone_term, :interface, z.interface),
      else: zone_term

    zone_term = if z.chains != [],
      do: Map.put(zone_term, :chains, Enum.map(z.chains, &chain_term/1)),
      else: zone_term

    zone_term = if z.deployments != [],
      do: Map.put(zone_term, :deployments, Enum.map(z.deployments, fn {n, r} -> %{pod: n, replicas: r} end)),
      else: zone_term

    zone_term = if z.steers != [],
      do: Map.put(zone_term, :steers, z.steers),
      else: zone_term

    zone_term = if z.containers != [],
      do: Map.put(zone_term, :containers, Enum.map(z.containers, &container_term/1)),
      else: zone_term

    zone_term
  end

  defp chain_term(chain) do
    chain
    |> Enum.reject(fn {_k, v} -> v == nil end)
    |> Map.new()
  end

  defp container_term(ct) do
    base = %{
      name: ct.name,
      binary: ct.binary,
      ip: ct.ip,
      ports: ct.ports,
      limits: ct.limits,
      restart: ct.restart,
      seccomp: ct.seccomp,
      uid: ct.uid,
      gid: ct.gid,
      args: ct.args,
      caps: ct.caps
    }

    base = if ct.image, do: Map.put(base, :image, ct.image), else: base
    base = if ct.firewall, do: Map.put(base, :firewall, ct.firewall), else: base
    base = if ct.health_check, do: Map.put(base, :health_check, ct.health_check), else: base

    base
    |> Enum.reject(fn {_k, v} -> v == nil or v == [] or v == %{} end)
    |> Map.new()
  end
end
