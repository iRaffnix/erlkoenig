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
  Accumulates a single pod definition — the logical bracket around all
  containers that belong together.

  A pod has no runtime effect beyond grouping. Each `container` inside
  declares its own deployment: `zone:` (which IPVLAN zone it runs in)
  and `replicas:` (how many instances). There is no separate `attach`
  step — the container tells the compiler where and how many.

  ## Structure

      pod "three_tier", strategy: :one_for_one do
        container "nginx",
          binary: "/opt/nginx", args: ["8443"],
          zone: "containers", replicas: 3,
          restart: :permanent do
          nft do
            output do
              nft_rule :accept, ct_state: [:established, :related]
              nft_rule :drop
            end
          end
        end

        container "api",
          binary: "/opt/api", args: ["4000"],
          zone: "containers", replicas: 1,
          restart: :permanent
      end

  ## Required vs. optional

  - **Required** on `container`: `binary:`, `zone:`, `replicas:`, `restart:`
  - **Required** on `pod`: `strategy:`
  - **Optional** (with documented defaults): `args: []`, `limits: %{}`,
    `uid: 65534`, `gid: 65534`, `seccomp: :default`, `caps: []`
  """

  @valid_strategies [:one_for_one, :one_for_all, :rest_for_one]
  @valid_restart_policies [:permanent, :transient, :temporary]
  @valid_metrics [:memory, :cpu, :pids, :pressure, :oom_events]
  @valid_channels [:stdout, :stderr]
  @min_interval 1000

  defstruct name: nil,
            strategy: nil,
            containers: [],
            current_ct: nil,
            current_publish: nil,
            current_stream: nil,
            current_nft: nil,
            current_nft_chain: nil,
            nft_rules_acc: []

  def new(name, opts) when is_binary(name) do
    strategy = case Keyword.fetch(opts, :strategy) do
      {:ok, s} -> s
      :error ->
        raise CompileError,
          description: "pod #{inspect(name)}: strategy: is required " <>
            "(one of #{inspect(@valid_strategies)})"
    end
    unless strategy in @valid_strategies do
      raise CompileError,
        description: "pod #{inspect(name)}: invalid strategy #{inspect(strategy)}. " <>
          "Allowed: #{inspect(@valid_strategies)}"
    end
    %__MODULE__{name: name, strategy: strategy}
  end

  # --- Container lifecycle ---

  def begin_container(%__MODULE__{} = pod, name, opts) when is_binary(name) do
    binary  = require_opt!(opts, :binary, name, "path to the binary")
    zone    = require_opt!(opts, :zone, name, "IPVLAN zone name")
    replicas = require_opt!(opts, :replicas, name, "positive integer")
    restart  = require_opt!(opts, :restart, name,
                            "one of #{inspect(@valid_restart_policies)}")

    unless is_integer(replicas) and replicas > 0 do
      raise CompileError,
        description: "container #{inspect(name)}: replicas: must be a positive integer, got #{inspect(replicas)}"
    end
    unless restart in @valid_restart_policies do
      raise CompileError,
        description: "container #{inspect(name)}: invalid restart #{inspect(restart)}. " <>
          "Allowed: #{inspect(@valid_restart_policies)}"
    end

    ct = %{
      name: name,
      binary: to_string(binary),
      zone: to_string(zone),
      replicas: replicas,
      restart: restart,
      image: opts[:image] && to_string(opts[:image]),
      ports: opts[:ports] || [],
      limits: opts[:limits] || %{},
      seccomp: opts[:seccomp] || :default,
      uid: opts[:uid] || 65534,
      gid: opts[:gid] || 65534,
      args: opts[:args] || [],
      caps: opts[:caps] || [],
      volumes: [],
      publish: [],
      stream: nil
    }
    %{pod | current_ct: ct}
  end

  # --- Volume lifecycle (called from Erlkoenig.Stack.volume macro) ---

  def add_volume(%__MODULE__{current_ct: nil}, _entry) do
    raise CompileError,
      description: "volume must be declared inside a container block"
  end

  def add_volume(%__MODULE__{current_ct: ct} = pod, entry) when is_map(entry) do
    %{pod | current_ct: Map.update(ct, :volumes, [entry], &(&1 ++ [entry]))}
  end

  defp require_opt!(opts, key, ct_name, hint) do
    case Keyword.fetch(opts, key) do
      {:ok, v} -> v
      :error ->
        raise CompileError,
          description: "container #{inspect(ct_name)}: #{inspect(key)} is required (#{hint})"
    end
  end

  def end_container(%__MODULE__{current_ct: ct, containers: cts} = pod) do
    %{pod | containers: cts ++ [ct], current_ct: nil, current_publish: nil,
            current_stream: nil}
  end

  # --- Publish block lifecycle ---

  def begin_publish(%__MODULE__{current_ct: nil}, _interval) do
    raise CompileError,
      description: "publish must be inside a container block"
  end

  def begin_publish(%__MODULE__{} = pod, interval) when is_integer(interval) do
    if interval < @min_interval do
      raise CompileError,
        description: "publish interval must be >= #{@min_interval}ms, got: #{interval}"
    end
    %{pod | current_publish: %{interval: interval, metrics: []}}
  end

  def add_metric(%__MODULE__{current_publish: nil}, _metric) do
    raise CompileError,
      description: "metric must be inside a publish block"
  end

  def add_metric(%__MODULE__{current_publish: pub} = pod, metric) when is_atom(metric) do
    unless metric in @valid_metrics do
      raise CompileError,
        description: "unknown metric #{inspect(metric)}. " <>
          "Allowed: #{inspect(@valid_metrics)}"
    end
    if metric in pub.metrics do
      raise CompileError,
        description: "duplicate metric #{inspect(metric)} in publish block"
    end
    %{pod | current_publish: %{pub | metrics: pub.metrics ++ [metric]}}
  end

  def end_publish(%__MODULE__{current_publish: nil} = pod), do: pod

  def end_publish(%__MODULE__{current_publish: pub, current_ct: ct} = pod) do
    if pub.metrics == [] do
      raise CompileError,
        description: "publish block must contain at least one metric"
    end
    ct = %{ct | publish: ct.publish ++ [pub]}
    %{pod | current_ct: ct, current_publish: nil}
  end

  # --- Stream block lifecycle (SPEC-EK-011) ---

  def begin_stream(%__MODULE__{current_ct: nil}, _opts) do
    raise CompileError,
      description: "stream must be inside a container block"
  end

  def begin_stream(%__MODULE__{current_ct: %{stream: existing}}, _opts) when existing != nil do
    raise CompileError,
      description: "only one stream block per container allowed"
  end

  def begin_stream(%__MODULE__{} = pod, opts) do
    retention_days = case Keyword.get(opts, :retention) do
      nil -> 7
      {n, :days} when is_integer(n) and n > 0 -> n
      other ->
        raise CompileError,
          description: "stream retention must be {N, :days}, got: #{inspect(other)}"
    end
    max_bytes = case Keyword.get(opts, :max_bytes) do
      nil -> nil
      {n, :gb} when is_number(n) and n > 0 -> trunc(n * 1_073_741_824)
      {n, :mb} when is_number(n) and n > 0 -> trunc(n * 1_048_576)
      other ->
        raise CompileError,
          description: "stream max_bytes must be {N, :gb} or {N, :mb}, got: #{inspect(other)}"
    end
    %{pod | current_stream: %{channels: [], retention_days: retention_days, max_bytes: max_bytes}}
  end

  def add_channel(%__MODULE__{current_stream: nil}, _channel) do
    raise CompileError,
      description: "channel must be inside a stream block"
  end

  def add_channel(%__MODULE__{current_stream: stream} = pod, channel) when is_atom(channel) do
    unless channel in @valid_channels do
      raise CompileError,
        description: "unknown channel #{inspect(channel)}. Allowed: #{inspect(@valid_channels)}"
    end
    if channel in stream.channels do
      raise CompileError,
        description: "duplicate channel #{inspect(channel)} in stream block"
    end
    %{pod | current_stream: %{stream | channels: stream.channels ++ [channel]}}
  end

  def end_stream(%__MODULE__{current_stream: nil} = pod), do: pod

  def end_stream(%__MODULE__{current_stream: stream, current_ct: ct} = pod) do
    if stream.channels == [] do
      raise CompileError,
        description: "stream block must contain at least one channel"
    end
    ct = %{ct | stream: stream}
    %{pod | current_ct: ct, current_stream: nil}
  end

  # --- Per-container nft (SPEC-EK-023) ---

  def begin_nft(%__MODULE__{current_ct: nil}) do
    raise CompileError, description: "nft block must be inside a container"
  end
  def begin_nft(%__MODULE__{} = pod) do
    %{pod | current_nft: %{chains: []}, nft_rules_acc: []}
  end

  def end_nft(%__MODULE__{current_nft: nil} = pod), do: pod
  def end_nft(%__MODULE__{current_nft: nft, current_ct: ct} = pod) do
    ct = Map.put(ct, :nft, nft)
    %{pod | current_ct: ct, current_nft: nil}
  end

  def begin_nft_chain(%__MODULE__{current_nft: nil}, _hook, _opts) do
    raise CompileError, description: "output/input block must be inside an nft block"
  end
  def begin_nft_chain(%__MODULE__{} = pod, hook, opts) when hook in [:output, :input] do
    policy = Keyword.get(opts, :policy, :accept)
    chain = %{
      name: Atom.to_string(hook),
      hook: hook,
      type: :filter,
      priority: 0,
      policy: policy
    }
    %{pod | current_nft_chain: chain, nft_rules_acc: []}
  end

  def end_nft_chain(%__MODULE__{current_nft_chain: nil} = pod), do: pod
  def end_nft_chain(%__MODULE__{current_nft_chain: chain, current_nft: nft,
                                nft_rules_acc: rules} = pod) do
    chain = Map.put(chain, :rules, Enum.reverse(rules))
    nft = %{nft | chains: nft.chains ++ [chain]}
    %{pod | current_nft: nft, current_nft_chain: nil, nft_rules_acc: []}
  end

  def add_nft_rule(%__MODULE__{current_nft_chain: nil}, _action, _opts) do
    raise CompileError, description: "nft_rule must be inside an output or input block"
  end
  def add_nft_rule(%__MODULE__{} = pod, action, opts) do
    rule = {action, Map.new(opts)}
    %{pod | nft_rules_acc: [rule | pod.nft_rules_acc]}
  end

  # --- Validation ---

  def validate!(%__MODULE__{} = pod) do
    if pod.containers == [] do
      raise CompileError,
        description: "pod #{inspect(pod.name)}: must have at least one container"
    end

    Erlkoenig.Validation.check_uniqueness(pod.containers, :name,
                                          "container names in pod #{inspect(pod.name)}")
    :ok
  end

  # --- Term output ---

  def to_term(%__MODULE__{} = pod) do
    containers = Enum.map(pod.containers, fn ct ->
      ct_term = %{
        name: ct.name,
        binary: ct.binary,
        zone: ct.zone,
        replicas: ct.replicas,
        restart: ct.restart,
        ports: ct.ports,
        limits: ct.limits,
        seccomp: ct.seccomp,
        uid: ct.uid,
        gid: ct.gid,
        args: ct.args,
        caps: ct.caps
      }

      ct_term = if ct.image, do: Map.put(ct_term, :image, ct.image), else: ct_term

      ct_term = if ct[:publish] != nil and ct[:publish] != [] do
        publish_term = Enum.map(ct.publish, fn pub ->
          %{interval: pub.interval, metrics: pub.metrics}
        end)
        Map.put(ct_term, :publish, publish_term)
      else
        ct_term
      end

      ct_term = if ct[:stream] != nil do
        stream_term = %{channels: ct.stream.channels, retention_days: ct.stream.retention_days}
        stream_term = if ct.stream.max_bytes, do: Map.put(stream_term, :max_bytes, ct.stream.max_bytes), else: stream_term
        Map.put(ct_term, :stream, stream_term)
      else
        ct_term
      end

      ct_term = if ct[:nft] != nil do
        Map.put(ct_term, :nft, ct.nft)
      else
        ct_term
      end

      ct_term = if ct[:volumes] != nil and ct[:volumes] != [] do
        Map.put(ct_term, :volumes, ct.volumes)
      else
        ct_term
      end

      ct_term
      |> Enum.reject(fn {_k, v} -> v == nil or v == [] or v == %{} end)
      |> Map.new()
    end)

    %{
      name: pod.name,
      strategy: pod.strategy,
      containers: containers
    }
  end
end
