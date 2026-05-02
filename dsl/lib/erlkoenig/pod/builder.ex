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
  declares its own deployment: `zone:` (which IPVLAN zone it runs in).
  Multiple instances should be declared explicitly with `for_each` in
  the DSL. There is no separate `attach`
  step — the container tells the compiler where it runs.

  ## Structure

      pod "three_tier", strategy: :one_for_one do
        container "nginx",
          binary: "/opt/nginx", args: ["8443"],
          zone: "containers",
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
          zone: "containers",
          restart: :permanent
      end

  ## Required vs. optional

  - **Required** on `container`: `binary:`, `zone:`, `restart:`
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
    replicas = Keyword.get(opts, :replicas, 1)
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

    validate_signature!(name, opts[:signature])
    validate_files!(name, opts[:files])

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
      env: opts[:env] || %{},
      signature: opts[:signature],
      files: opts[:files] || %{},
      volumes: [],
      socket_mounts: [],
      requires: [],
      publish: [],
      stream: nil
    }
    %{pod | current_ct: ct}
  end

  # --- conn_limit (SPEC-EK-028 phase 1, tracker column `conn_cur`) ---
  #
  # Chain-scoped. Validates opts, then re-enters the normal nft_rule
  # emission path so the resulting `{:connlimit_drop, %{max: N}}`
  # entry shows up in the chain's rule list exactly like a hand-
  # written `nft_rule :connlimit_drop, max: 100`. Glasbox: one DSL
  # line becomes exactly one nft rule, visible in place.

  def add_conn_limit(%__MODULE__{current_nft_chain: nil}, _opts) do
    raise CompileError,
      description:
        "conn_limit must appear inside an `nft do input ... end` " <>
        "(or output) block — it compiles to a chain rule, not to " <>
        "a hidden synthesis"
  end

  def add_conn_limit(%__MODULE__{} = pod, opts) when is_list(opts) do
    {action, rule_opts} = Erlkoenig.Nft.ChainBuilder.compile_conn_limit!(opts)
    add_nft_rule(pod, action, rule_opts)
  end

  # --- Volume lifecycle (called from Erlkoenig.Stack.volume macro) ---

  def add_volume(%__MODULE__{current_ct: nil}, _entry) do
    raise CompileError,
      description: "volume must be declared inside a container block"
  end

  def add_volume(%__MODULE__{current_ct: ct} = pod, entry) when is_map(entry) do
    %{pod | current_ct: Map.update(ct, :volumes, [entry], &(&1 ++ [entry]))}
  end

  # --- Capability requirements (called from Erlkoenig.Stack.requires macro) ---

  def add_requires(%__MODULE__{current_ct: nil}, _capability, _opts) do
    raise CompileError,
      description: "requires must be declared inside a container block"
  end

  def add_requires(%__MODULE__{current_ct: ct} = pod, capability, opts)
      when is_atom(capability) and is_list(opts) do
    if capability in ct.requires do
      pod
    else
      spec = Erlkoenig.Capabilities.fetch!(capability)
      %{pod | current_ct: apply_capability(ct, capability, spec, opts)}
    end
  end

  defp apply_capability(ct, capability, %{kind: :network}, _opts) do
    %{ct | requires: ct.requires ++ [capability]}
  end

  defp apply_capability(ct, capability, %{kind: :socket} = spec, _opts) do
    dir = Erlkoenig.Capabilities.socket_dir()
    dir_mount = %{host: dir, container: dir, read_only: false}

    socket_mounts =
      if Enum.any?(ct.socket_mounts, &(&1.host == dir)) do
        ct.socket_mounts
      else
        ct.socket_mounts ++ [dir_mount]
      end

    # libpq + similar tools want a directory in their env var, not
    # the socket-file path. Capabilities override via :env_value.
    env_value = Map.get(spec, :env_value, spec.container_socket)

    %{ct |
       requires: ct.requires ++ [capability],
       socket_mounts: socket_mounts,
       env: Map.put(ct.env, spec.env_var, env_value)}
  end

  defp apply_capability(ct, capability, %{kind: :dns_allowlist}, opts) do
    hosts =
      case Keyword.fetch(opts, :hosts) do
        {:ok, list} when is_list(list) and list != [] ->
          Enum.map(list, &validate_host_pattern!/1)

        _ ->
          raise CompileError,
            description:
              "requires :#{capability} needs a non-empty :hosts list, " <>
                "e.g. requires :\"dns.allowlist\", hosts: [\"api.openai.com\"]"
      end

    # We carry the allowlist as a top-level field on the container
    # term — separate from `:requires` so the existing readers don't
    # need to learn a new shape. The Erlang side reads `:dns_allowlist`
    # at spawn time and registers it against the container's IP.
    ct
    |> Map.put(:requires, ct.requires ++ [capability])
    |> Map.put(:dns_allowlist, hosts)
  end

  # Hostname pattern: bare hostname or `*.<rest>` wildcard.  We accept
  # binaries, atoms, and charlists; everything else is a compile error
  # so typos don't reach the runtime as silent allow-everything.
  #
  # Why strict validation: the DNS filter matches on the Question
  # Name of each DNS query verbatim.  If the operator writes
  # `"http://api.example.com"` (a URL, not a hostname) into the
  # allowlist, NO DNS query will ever match it because queries don't
  # carry schemes — the container is silently blackholed.
  defp validate_host_pattern!(h) when is_binary(h) do
    if valid_host_pattern?(h), do: h, else: bad_host!(h)
  end
  defp validate_host_pattern!(h) when is_atom(h) do
    validate_host_pattern!(Atom.to_string(h))
  end
  defp validate_host_pattern!(h) when is_list(h) do
    if List.ascii_printable?(h) do
      validate_host_pattern!(List.to_string(h))
    else
      bad_host!(h)
    end
  end
  defp validate_host_pattern!(h), do: bad_host!(h)

  # A DNS-filter-matchable pattern: optional `*.` wildcard followed
  # by one-or-more labels separated by `.`.  Each label is 1-63
  # chars of letters/digits/hyphens, not starting or ending in
  # hyphen.  Total length ≤253.
  defp valid_host_pattern?(s) when is_binary(s) do
    byte_size(s) > 0 and byte_size(s) <= 253 and
      Regex.match?(
        ~r/^\*\.(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))+)$|^(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*)$/,
        s
      )
  end

  defp bad_host!(h) do
    raise CompileError,
      description:
        "dns.allowlist host pattern must be a bare hostname or `*.<rest>` " <>
          "wildcard (no scheme, no path, no spaces), got #{inspect(h)}.  " <>
          "The DNS filter matches DNS query names verbatim — URLs or " <>
          "patterns with non-hostname characters will never match, " <>
          "silently blackholing all container egress."
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
  #
  # Owner model (SPEC-NFT-OWNERSHIP-SPLIT §7, phase 6e.0.b):
  # the container-local nft block carries `owner: :in_container`
  # at the top of the block IR and denormalized on each chain.
  # Container nft is netns-local — no layout-bridge use, no fixed
  # host table name — so the owner tag is a pure Glasbox/audit
  # signal, not a routing decision.

  def begin_nft(%__MODULE__{current_ct: nil}) do
    raise CompileError, description: "nft block must be inside a container"
  end
  def begin_nft(%__MODULE__{} = pod) do
    %{pod | current_nft: %{owner: :in_container, chains: []}, nft_rules_acc: []}
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
      owner: :in_container,
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

      # Runtime convention is `:image_path` (see erlkoenig_config:build_spawn_opts).
      # The DSL option is still `image:` for operator ergonomics.
      ct_term = if ct.image, do: Map.put(ct_term, :image_path, ct.image), else: ct_term

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

      # Capability declarations and their injections.
      ct_term = if ct[:requires] != nil and ct[:requires] != [] do
        Map.put(ct_term, :requires, ct.requires)
      else
        ct_term
      end

      ct_term = if ct[:socket_mounts] != nil and ct[:socket_mounts] != [] do
        Map.put(ct_term, :socket_mounts, ct.socket_mounts)
      else
        ct_term
      end

      ct_term = case ct[:dns_allowlist] do
        nil -> ct_term
        []  -> ct_term
        hosts -> Map.put(ct_term, :dns_allowlist, hosts)
      end

      ct_term = if ct[:env] != nil and ct[:env] != %{} do
        Map.put(ct_term, :env, ct.env)
      else
        ct_term
      end

      # Signature gate (SPEC-EK-017). Two shapes:
      #   signature: :required   → runtime enforces trusted sig against installed roots
      #   signature: "/path.sig" → explicit detached signature file
      ct_term = case ct[:signature] do
        nil       -> ct_term
        :required -> Map.put(ct_term, :signature_required, true)
        path when is_binary(path) or is_list(path) ->
          Map.put(ct_term, :sig_path, to_string(path))
      end

      # Injected files (SPEC-EK-024 §4). Map of container-path → contents.
      ct_term = if is_map(ct[:files]) and ct[:files] != %{} do
        Map.put(ct_term, :files, ct.files)
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

  # Validators — fail at compile time so the operator sees the error
  # at `mix compile` rather than at container spawn.

  defp validate_signature!(_name, nil), do: :ok
  defp validate_signature!(_name, :required), do: :ok
  defp validate_signature!(_name, path) when is_binary(path), do: :ok
  defp validate_signature!(name, other) do
    raise CompileError,
      description: "container #{inspect(name)}: signature: must be " <>
        ":required or a string path, got #{inspect(other)}"
  end

  defp validate_files!(_name, nil), do: :ok
  defp validate_files!(name, files) when is_map(files) do
    Enum.each(files, fn
      {path, content} when (is_binary(path) or is_list(path)) and
                            (is_binary(content) or is_list(content)) -> :ok
      {path, content} ->
        raise CompileError,
          description: "container #{inspect(name)}: files entry " <>
            "#{inspect(path)} → #{inspect(content)}: both key and " <>
            "value must be strings"
    end)
  end
  defp validate_files!(name, other) do
    raise CompileError,
      description: "container #{inspect(name)}: files: must be a map " <>
        "of \"/path\" => \"contents\", got #{inspect(other)}"
  end
end
