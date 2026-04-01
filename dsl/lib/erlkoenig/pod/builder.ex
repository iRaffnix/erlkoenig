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

defmodule Erlkoenig.Pod.Builder do
  @moduledoc """
  Accumulates pod definitions — a group of containers with
  per-container firewall chains and inter-container forwarding rules.

  A pod is a **template**. It produces no kernel objects by itself.
  Only when deployed via `deploy "pod", replicas: N` inside a zone
  does the compiler expand it into concrete containers with IPs,
  veth pairs, and nft chains.

  ## Container References

  Inside a pod, `@container_name` references are used in `iif:` and
  `oif:` rule options to specify inter-container traffic paths.
  These are resolved to concrete veth names at deploy time.

  ## Structure

      pod "webstack" do
        container "frontend", binary: "/opt/frontend" do
          chain "inbound", policy: :drop do
            rule :accept, ct: :established
            rule :accept, tcp: 8080
            rule :drop
          end
        end

        chain "forward", policy: :drop do
          rule :accept, ct: :established
          rule :accept, iif: @frontend, oif: @api, tcp: 4000
          rule :drop
        end
      end
  """

  defstruct name: nil,
            containers: [],
            current_ct: nil,
            chains: [],
            rules_acc: []

  def new(name) when is_binary(name) do
    %__MODULE__{name: name}
  end

  # --- Container lifecycle ---

  def begin_container(%__MODULE__{} = pod, name, opts) when is_binary(name) do
    ct = %{
      name: name,
      binary: opts[:binary] && to_string(opts[:binary]),
      image: opts[:image] && to_string(opts[:image]),
      ports: opts[:ports] || [],
      limits: opts[:limits] || %{},
      restart: opts[:restart] || :no_restart,
      seccomp: opts[:seccomp] || :default,
      uid: opts[:uid] || 65534,
      gid: opts[:gid] || 65534,
      args: opts[:args] || [],
      caps: opts[:caps] || [],
      chains: [],
      rules_acc: []
    }
    %{pod | current_ct: ct}
  end

  def end_container(%__MODULE__{current_ct: ct, containers: cts} = pod) do
    %{pod | containers: cts ++ [ct], current_ct: nil}
  end

  # --- Chain/Rule inside container ---

  def begin_chain(%__MODULE__{current_ct: ct} = pod, _name, _opts) when ct != nil do
    %{pod | current_ct: %{ct | rules_acc: []}}
  end

  def begin_chain(%__MODULE__{current_ct: nil} = pod, _name, _opts) do
    %{pod | rules_acc: []}
  end

  def push_rule(%__MODULE__{current_ct: ct} = pod) when ct != nil do
    pod
  end

  def end_chain(%__MODULE__{current_ct: ct} = pod, name, opts) when ct != nil do
    chain = build_chain(name, opts, ct.rules_acc)
    %{pod | current_ct: %{ct | chains: ct.chains ++ [chain], rules_acc: []}}
  end

  def end_chain(%__MODULE__{current_ct: nil} = pod, name, opts) do
    chain = build_chain(name, opts, pod.rules_acc)
    %{pod | chains: pod.chains ++ [chain], rules_acc: []}
  end

  defp build_chain(name, opts, rules) do
    base = %{name: name, rules: rules}
    base = if opts[:hook], do: Map.put(base, :hook, opts[:hook]), else: base
    base = if opts[:type], do: Map.put(base, :type, opts[:type]), else: base
    base = if opts[:priority], do: Map.put(base, :priority, opts[:priority]), else: base
    base = if opts[:policy], do: Map.put(base, :policy, opts[:policy]), else: base
    base
  end

  # --- Rule accumulator ---

  def push_rule_to_ct(%__MODULE__{current_ct: ct} = pod, rule) when ct != nil do
    %{pod | current_ct: %{ct | rules_acc: ct.rules_acc ++ [rule]}}
  end

  def push_rule_to_pod(%__MODULE__{} = pod, rule) do
    %{pod | rules_acc: pod.rules_acc ++ [rule]}
  end

  # --- Validation ---

  def validate!(%__MODULE__{} = pod) do
    if pod.containers == [] do
      raise CompileError,
        description: "pod #{inspect(pod.name)}: must have at least one container"
    end

    names = Enum.map(pod.containers, & &1.name)
    dupes = names -- Enum.uniq(names)
    if dupes != [] do
      raise CompileError,
        description: "pod #{inspect(pod.name)}: duplicate container names: #{inspect(Enum.uniq(dupes))}"
    end

    Enum.each(pod.containers, fn ct ->
      if ct.binary == nil do
        raise CompileError,
          description: "pod #{inspect(pod.name)}/#{ct.name}: missing binary"
      end
    end)

    # Validate @ref in chain rules
    validate_refs!(pod, names)

    :ok
  end

  defp validate_refs!(pod, container_names) do
    all_chains = pod.chains ++ Enum.flat_map(pod.containers, & &1.chains)

    Enum.each(all_chains, fn chain ->
      Enum.each(chain.rules, fn
        {:rule, _verdict, opts} when is_map(opts) ->
          check_ref(opts, :iif, pod.name, container_names)
          check_ref(opts, :oif, pod.name, container_names)
        _ -> :ok
      end)
    end)
  end

  defp check_ref(opts, key, pod_name, container_names) do
    case Map.get(opts, key) do
      {:ref, name} ->
        unless name in container_names do
          raise CompileError,
            description: "pod #{inspect(pod_name)}: @#{name} references unknown container. " <>
              "Known: #{inspect(container_names)}"
        end
      _ -> :ok
    end
  end

  # --- Term output ---

  def to_term(%__MODULE__{} = pod) do
    containers = Enum.map(pod.containers, fn ct ->
      ct_term = %{
        name: ct.name,
        binary: ct.binary,
        ports: ct.ports,
        limits: ct.limits,
        restart: ct.restart,
        seccomp: ct.seccomp,
        uid: ct.uid,
        gid: ct.gid,
        args: ct.args,
        caps: ct.caps
      }

      ct_term = if ct.image, do: Map.put(ct_term, :image, ct.image), else: ct_term

      ct_term = if ct.chains != [] do
        fw = %{chains: Enum.map(ct.chains, &chain_to_term/1)}
        Map.put(ct_term, :firewall, fw)
      else
        ct_term
      end

      ct_term
      |> Enum.reject(fn {_k, v} -> v == nil or v == [] or v == %{} end)
      |> Map.new()
    end)

    base = %{
      name: pod.name,
      containers: containers
    }

    if pod.chains != [] do
      Map.put(base, :chains, Enum.map(pod.chains, &chain_to_term/1))
    else
      base
    end
  end

  defp chain_to_term(chain) do
    chain
    |> Enum.reject(fn {_k, v} -> v == nil end)
    |> Map.new()
  end
end
