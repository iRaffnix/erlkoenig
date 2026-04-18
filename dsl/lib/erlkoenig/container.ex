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

defmodule Erlkoenig.Container do
  @moduledoc """
  DSL macros for defining Erlkoenig containers.

  ## Example

      defmodule MyContainers do
        use Erlkoenig.Container

        defaults do
          firewall :standard
        end

        container :web_api do
          binary "/opt/bin/api_server"
          ip {10, 0, 0, 10}
          ports [{8080, 80}, {8443, 443}]
          env %{"PORT" => "80"}
          firewall :strict, allow_tcp: [80, 443]
        end

        container :worker do
          binary "/opt/bin/worker"
          ip {10, 0, 0, 20}
          args ["--threads", "4"]
        end
      end

      MyContainers.containers()        # => list of term maps
      MyContainers.container(:web_api)  # => single term map
  """

  alias Erlkoenig.Container.Builder

  defmacro __using__(_opts) do
    quote do
      import Erlkoenig.Container
      Module.register_attribute(__MODULE__, :ct_builders, accumulate: true)
      Module.register_attribute(__MODULE__, :ct_current, accumulate: false)
      Module.register_attribute(__MODULE__, :ct_defaults, accumulate: false)
      Module.register_attribute(__MODULE__, :ct_guard_acc, accumulate: false)
      Module.register_attribute(__MODULE__, :ct_policy_acc, accumulate: false)
      Module.register_attribute(__MODULE__, :ct_rootfs_acc, accumulate: false)
      @ct_defaults %{}
      @ct_guard_acc %{}
      @ct_policy_acc %{}
      @ct_rootfs_acc nil

      @before_compile Erlkoenig.Container
    end
  end

  defmacro __before_compile__(_env) do
    quote do
      def containers do
        @ct_builders
        |> Enum.reverse()
        |> Enum.map(fn builder ->
          Builder.to_term(builder)
        end)
      end

      def spawn_opts do
        @ct_builders
        |> Enum.reverse()
        |> Enum.map(fn builder ->
          {builder.name, builder.binary, Builder.to_spawn_opts(builder)}
        end)
      end

      def write!(path) do
        terms = containers()
        config = %{containers: terms, defaults: @ct_defaults}
        formatted = :io_lib.format(~c"~tp.~n", [config])
        File.write!(path, formatted)
      end
    end
  end

  # --- Defaults ---

  defmacro defaults(do: block) do
    quote do
      @ct_defaults %{}
      unquote(block)
    end
  end

  # --- Container definition ---

  defmacro container(name, do: block) do
    quote do
      @ct_current Builder.new(unquote(name))
      unquote(block)
      @ct_builders @ct_current
    end
  end

  # --- Container properties ---

  defmacro binary(path) do
    quote do: @ct_current Builder.set_binary(@ct_current, unquote(path))
  end

  defmacro signature(mode_or_path) do
    quote do: @ct_current Builder.set_signature(@ct_current, unquote(mode_or_path))
  end

  defmacro ip(addr) do
    quote do: @ct_current Builder.set_ip(@ct_current, unquote(addr))
  end

  defmacro ports(port_list) do
    quote do: @ct_current Builder.set_ports(@ct_current, unquote(port_list))
  end

  defmacro args(arg_list) do
    quote do: @ct_current Builder.set_args(@ct_current, unquote(arg_list))
  end

  defmacro env(env_map) do
    quote do: @ct_current Builder.set_env(@ct_current, unquote(env_map))
  end

  # --- Volumes (persistent bind-mount directories) ---

  @doc """
  Declare a persistent volume for the container.

  ## Example

      volume "/data/db",     persist: "archive-db"
      volume "/var/log",     persist: "archive-logs"
      volume "/etc/config",  persist: "shared-config", read_only: true

      # Full mount-option string (parsed by erlkoenig_mount_opts):
      volume "/srv/in",  persist: "ingest",
                         opts: "ro,nosuid,nodev,noexec,relatime"

  The `persist` key is required and must match `[a-z0-9][a-z0-9_-]*`.
  The host path is resolved centrally by the core:
  `/var/lib/erlkoenig/volumes/<container>/<persist>/`

  ## Options

    * `:persist`    — (required) host-side persistent store name
    * `:read_only`  — convenience boolean; sets `ro` on the mount.
      Equivalent to `opts: "ro"`.
    * `:opts`       — full mount-option string in `mount(8)` syntax.
      Takes precedence over `:read_only` when both are given.
      Parsed at config-load time by `erlkoenig_mount_opts:parse/1`;
      typos (`nosudi`) fail loud with a clear error.
  """
  defmacro volume(container_path, opts) do
    quote do
      persist_name = Keyword.fetch!(unquote(opts), :persist)
      read_only   = Keyword.get(unquote(opts), :read_only, false)
      mount_opts  = Keyword.get(unquote(opts), :opts)
      ephemeral   = Keyword.get(unquote(opts), :ephemeral, false)
      quota       = Keyword.get(unquote(opts), :quota)

      unless is_boolean(ephemeral) do
        raise ArgumentError,
          "volume ephemeral: expected a boolean, got #{inspect(ephemeral)}"
      end

      entry = %{container: unquote(container_path),
                persist: persist_name,
                read_only: read_only,
                ephemeral: ephemeral}

      entry =
        case mount_opts do
          nil -> entry
          s when is_binary(s) -> Map.put(entry, :opts, s)
          other ->
            raise ArgumentError,
              "volume opts: expected a binary string, got #{inspect(other)}"
        end

      entry =
        case quota do
          nil -> entry
          q when is_binary(q) -> Map.put(entry, :quota, q)
          q when is_integer(q) and q >= 0 -> Map.put(entry, :quota, q)
          other ->
            raise ArgumentError,
              "volume quota: expected a size string (\"1G\") or non-negative integer, got #{inspect(other)}"
        end

      @ct_current Builder.add_volume(@ct_current, entry)
    end
  end

  # --- Firewall (inline nftables rules) ---

  defmacro firewall(do: block) do
    quote do
      unquote(block)
    end
  end

  @doc "Generic rule macro for per-container firewall. Same syntax as host firewall."
  defmacro rule(verdict, opts \\ []) do
    quote do
      @ct_current Builder.add_fw_rule(@ct_current,
        ErlkoenigNft.Firewall.Builder.build_rule(unquote(verdict), unquote(opts)))
    end
  end

  defmacro counters(names) do
    quote do: @ct_current Builder.set_fw_counters(@ct_current, unquote(names))
  end

  defmacro set(name, type) do
    quote do: @ct_current Builder.add_fw_set(@ct_current, unquote(name), unquote(type))
  end

  # --- Guard (threat detection) ---

  defmacro guard(do: block) do
    quote do
      @ct_guard_acc %{}
      unquote(block)
      @ct_current Builder.set_guard(@ct_current, @ct_guard_acc)
    end
  end

  defmacro detect(type, opts) do
    quote do
      threshold = Keyword.fetch!(unquote(opts), :threshold)
      window = Keyword.fetch!(unquote(opts), :window)
      @ct_guard_acc Map.put(@ct_guard_acc, unquote(type), {threshold, window})
    end
  end

  defmacro ban_duration(seconds) do
    quote do: @ct_guard_acc Map.put(@ct_guard_acc, :ban_duration, unquote(seconds))
  end

  # --- Restart ---

  defmacro restart(policy) do
    quote do: @ct_current Builder.set_restart(@ct_current, unquote(policy))
  end

  # --- Files ---

  defmacro files(file_map) do
    quote do: @ct_current Builder.set_files(@ct_current, unquote(file_map))
  end

  defmacro file(path, content) when is_binary(content) do
    quote do: @ct_current Builder.add_file(@ct_current, unquote(path), unquote(content))
  end

  defmacro file(path, opts) when is_list(opts) do
    quote do
      entry = case unquote(opts) do
        [from: :host] ->
          %{path: unquote(path), source: {:host, unquote(path)}}
        [from: host_path] when is_binary(host_path) ->
          %{path: unquote(path), source: {:host, host_path}}
        [content: content] when is_binary(content) ->
          %{path: unquote(path), source: {:inline, content}}
      end
      @ct_rootfs_acc Map.update!(@ct_rootfs_acc, :files, &(&1 ++ [entry]))
    end
  end

  # --- Rootfs (FUSE rootfs definition) ---

  defmacro rootfs(do: block) do
    quote do
      @ct_rootfs_acc %{files: [], tmpfs: []}
      unquote(block)
      @ct_current Builder.set_rootfs(@ct_current, @ct_rootfs_acc)
      @ct_rootfs_acc nil
    end
  end

  defmacro base(name) when is_atom(name) do
    quote do
      @ct_rootfs_acc Map.put(@ct_rootfs_acc, :base, unquote(name))
    end
  end

  defmacro directory(container_path, opts) do
    quote do
      from = Keyword.fetch!(unquote(opts), :from)
      entry = %{path: unquote(container_path), source: {:directory, from}}
      @ct_rootfs_acc Map.update!(@ct_rootfs_acc, :files, &(&1 ++ [entry]))
    end
  end

  defmacro tmpfs(path, opts \\ []) do
    quote do
      size = Keyword.get(unquote(opts), :size, "64M")
      entry = %{path: unquote(path), size: size}
      @ct_rootfs_acc Map.update!(@ct_rootfs_acc, :tmpfs, &(&1 ++ [entry]))
    end
  end

  # --- DNS Name ---

  defmacro dns_name(name) do
    quote do: @ct_current Builder.set_dns_name(@ct_current, unquote(name))
  end

  # --- Limits ---

  defmacro limits(opts) do
    quote do
      limits_term = Erlkoenig.Limits.build(unquote(opts))
      @ct_current Builder.set_limits(@ct_current, limits_term)
    end
  end

  # --- Health Check ---

  defmacro health_check(opts) do
    quote do
      @ct_current Builder.set_health_check(@ct_current, unquote(opts))
    end
  end

  # --- Zone ---

  defmacro zone(name) when is_atom(name) do
    quote do: @ct_current Builder.set_zone(@ct_current, unquote(name))
  end

  # --- Capabilities ---

  defmacro caps(cap_list) do
    quote do: @ct_current Builder.set_caps(@ct_current, unquote(cap_list))
  end

  # --- Seccomp ---

  defmacro seccomp(profile) when is_atom(profile) do
    quote do
      seccomp_term = Erlkoenig.Seccomp.get(unquote(profile))
      @ct_current %{@ct_current | seccomp: seccomp_term}
    end
  end

  # --- Observe (eBPF tracepoint metrics) ---

  @doc """
  Enable eBPF tracepoint metrics for this container.

  Available metrics: `:forks`, `:execs`, `:exits`, `:oom`, `:all`

  ## Example

      observe :all
      observe :forks, :execs, :oom
  """
  defmacro observe(metric) do
    quote do
      metrics = Erlkoenig.Container.expand_observe([unquote(metric)])
      @ct_current Builder.set_observe(@ct_current, metrics)
    end
  end

  defmacro observe(m1, m2) do
    quote do
      metrics = Erlkoenig.Container.expand_observe([unquote(m1), unquote(m2)])
      @ct_current Builder.set_observe(@ct_current, metrics)
    end
  end

  defmacro observe(m1, m2, m3) do
    quote do
      metrics = Erlkoenig.Container.expand_observe([unquote(m1), unquote(m2), unquote(m3)])
      @ct_current Builder.set_observe(@ct_current, metrics)
    end
  end

  defmacro observe(m1, m2, m3, m4) do
    quote do
      metrics = Erlkoenig.Container.expand_observe([unquote(m1), unquote(m2), unquote(m3), unquote(m4)])
      @ct_current Builder.set_observe(@ct_current, metrics)
    end
  end

  def expand_observe(metrics) do
    if :all in metrics do
      [:forks, :execs, :exits, :oom]
    else
      valid = [:forks, :execs, :exits, :oom]
      Enum.each(metrics, fn m ->
        unless m in valid, do: raise(ArgumentError, "unknown observe metric: #{inspect(m)}")
      end)
      metrics
    end
  end

  # --- Policy (reactive rules on eBPF events) ---

  @doc """
  Define reactive policies based on eBPF events.

  ## Example

      policy do
        max_forks 50, per: :minute
        max_forks 10, per: :second
        on_oom :restart
        on_fork_flood :kill
        allowed_comms ["app", "worker"]
        on_unexpected_exec :kill
      end
  """
  defmacro policy(do: block) do
    quote do
      @ct_policy_acc %{}
      unquote(block)
      @ct_current Builder.set_policy(@ct_current, @ct_policy_acc)
    end
  end

  defmacro max_forks(count, opts) do
    quote do
      per = Keyword.fetch!(unquote(opts), :per)
      key = case per do
        :second -> :max_forks_per_sec
        :minute -> :max_forks_per_min
        other -> raise ArgumentError, "max_forks per: must be :second or :minute, got #{inspect(other)}"
      end
      @ct_policy_acc Map.put(@ct_policy_acc, key, unquote(count))
    end
  end

  defmacro on_oom(action) when action in [:restart, :kill, :alert] do
    quote do: @ct_policy_acc Map.put(@ct_policy_acc, :on_oom, unquote(action))
  end

  defmacro on_fork_flood(action) when action in [:kill, :alert] do
    quote do: @ct_policy_acc Map.put(@ct_policy_acc, :on_fork_flood, unquote(action))
  end

  defmacro allowed_comms(comm_list) do
    quote do: @ct_policy_acc Map.put(@ct_policy_acc, :allowed_comms, unquote(comm_list))
  end

  defmacro on_unexpected_exec(action) when action in [:kill, :alert] do
    quote do: @ct_policy_acc Map.put(@ct_policy_acc, :on_unexpected_exec, unquote(action))
  end
end
