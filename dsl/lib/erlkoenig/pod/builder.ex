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

  @valid_strategies [:one_for_one, :one_for_all, :rest_for_one]
  @valid_metrics [:memory, :cpu, :pids, :pressure, :oom_events]
  @valid_channels [:stdout, :stderr]
  @min_interval 1000

  defstruct name: nil,
            strategy: :one_for_one,
            containers: [],
            current_ct: nil,
            current_publish: nil,
            current_stream: nil

  def new(name, opts \\ []) when is_binary(name) do
    strategy = Keyword.get(opts, :strategy, :one_for_one)
    unless strategy in @valid_strategies do
      raise CompileError,
        description: "pod #{inspect(name)}: invalid strategy #{inspect(strategy)}. " <>
          "Allowed: #{inspect(@valid_strategies)}"
    end
    %__MODULE__{name: name, strategy: strategy}
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
      publish: [],
      stream: nil
    }
    %{pod | current_ct: ct}
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

  # --- Validation ---

  def validate!(%__MODULE__{} = pod) do
    if pod.containers == [] do
      raise CompileError,
        description: "pod #{inspect(pod.name)}: must have at least one container"
    end

    Erlkoenig.Validation.check_uniqueness(pod.containers, :name, "container names in pod #{inspect(pod.name)}")

    Enum.each(pod.containers, fn ct ->
      if ct.binary == nil do
        raise CompileError,
          description: "pod #{inspect(pod.name)}/#{ct.name}: missing binary"
      end
    end)

    :ok
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
