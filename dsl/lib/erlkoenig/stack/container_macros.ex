defmodule Erlkoenig.Stack.ContainerMacros do
  @moduledoc false

  # ═══════════════════════════════════════════════════════════
  # pod — container group template
  # ═══════════════════════════════════════════════════════════

  @doc """
  Define a pod — a group of containers that are deployed and supervised together.

  A pod is a **template**. It produces no running processes by itself.
  Only when deployed via `attach/2` does the compiler expand it into
  concrete containers with IPs, IPVLAN slaves, and cgroups.

  ## Required Options

  | Option | Type | Description |
  |--------|------|-------------|
  | `strategy:` | `:one_for_one` \\| `:one_for_all` \\| `:rest_for_one` | OTP supervisor restart strategy for the pod's containers |

  ## Strategies

  - `:one_for_one` — each container restarts independently
  - `:one_for_all` — if one container crashes, all containers in the pod restart
  - `:rest_for_one` — if a container crashes, it and all containers started after it restart (order matters)

  ## Examples

      # Three-tier stack as one logical bracket
      pod "three_tier", strategy: :one_for_one do
        container "nginx",
          binary: "/opt/nginx", args: ["8443"],
          zone: "containers", replicas: 3,
          restart: :permanent

        container "api",
          binary: "/opt/api", args: ["4000"],
          zone: "containers", replicas: 1,
          restart: :permanent

        container "postgres",
          binary: "/opt/postgres",
          zone: "containers", replicas: 1,
          restart: :permanent
      end

      # Tightly coupled: app + cache restart together
      pod "backend", strategy: :one_for_all do
        container "app",   binary: "/opt/app",   zone: "net", replicas: 1, restart: :permanent
        container "cache", binary: "/opt/redis", zone: "net", replicas: 1, restart: :permanent
      end
  """
  defmacro pod(name, opts, do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :pod)

    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.new(unquote(name), unquote(opts))
      unquote(block)
      @stack_pods var!(ek_pod_builder)
    end
  end

  # Helpful error when strategy: is omitted (pod "X" do ... end)
  defmacro pod(name, do: _block) do
    raise CompileError,
      description:
        "pod #{inspect(name)}: strategy: is required " <>
          "(one of :one_for_one, :one_for_all, :rest_for_one)"
  end

  @doc """
  Define a container inside a pod.

  Each container runs a single Linux process in its own network namespace
  with an isolated cgroup. Containers within the same pod share a supervisor
  but have separate network stacks.

  Can be used with or without a `do` block. The block is needed for
  `publish` (cgroup metrics) or future per-container configuration.

  ## Required Options

  | Option | Type | Description |
  |--------|------|-------------|
  | `binary:` | `string` | Absolute path to the executable to run |
  | `zone:` | `string` | IPVLAN zone name (must match an `ipvlan` declared on `host`) |
  | `restart:` | `:permanent` \\| `:transient` \\| `:temporary` | OTP restart policy |

  ## Optional Options (with sensible defaults)

  | Option | Type | Default | Description |
  |--------|------|---------|-------------|
  | `replicas:` | `pos_integer` | `1` | Legacy convenience. Prefer explicit `for_each` loops with one container per instance. |
  | `args:` | `[string]` | `[]` | Command-line arguments passed to the binary |
  | `limits:` | `map` | `%{}` | Resource limits: `memory` (bytes), `cpu` (1-100%), `pids` (max processes) |
  | `seccomp:` | `:default` \\| `:none` | `:default` | Seccomp profile for syscall filtering |
  | `uid:` | `integer` | `65534` | User ID the process runs as (65534 = nobody) |
  | `gid:` | `integer` | `65534` | Group ID the process runs as |
  | `caps:` | `[atom]` | `[]` | Linux capabilities to keep (e.g. `[:net_bind_service]`) |
  | `ports:` | `[integer]` | `[]` | Ports the container listens on (informational) |
  | `health_check:` | `keyword` | none | Health check config: `port:`, `interval:` (ms), `retries:` |
  | `image:` | `string` | none | Container image path (alternative to binary) |

  ## Restart Policies (OTP)

  - `:permanent` — always restart on any exit
  - `:transient` — restart only on abnormal exit (non-zero or signalled)
  - `:temporary` — never restart (one-shot)

  Backoff: 1s, 2s, 4s, 8s, 16s, 30s (capped).

  ## Limits

      # 512 MB memory, 50% of one CPU core, max 100 processes
      container "worker",
        binary: "/opt/worker", zone: "work", replicas: 1, restart: :permanent,
        limits: %{memory: 536_870_912, cpu: 50, pids: 100}

  ## Examples

      # Minimal
      container "echo",
        binary: "/opt/echo", args: ["8080"],
        zone: "net", restart: :permanent

      # With cgroup metrics publishing
      for_each i <- 0..2 do
        container "nginx-\#{i}",
          binary: "/opt/nginx", args: ["8443"],
          zone: "dmz", restart: :permanent do
          publish interval: 2000 do
            metric :memory
            metric :cpu
            metric :pids
          end
        end
      end
  """
  defmacro container(name, opts) when is_list(opts) do
    Module.put_attribute(__CALLER__.module, :ek_container_nft, false)

    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.begin_container(
          var!(ek_pod_builder),
          to_string(unquote(name)),
          unquote(opts)
        )

      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_container(var!(ek_pod_builder))
    end
  end

  defmacro container(name, opts, do: block) when is_list(opts) do
    # Reset container nft context after expansion so host nft_rules
    # in nft_table blocks don't dispatch to the pod builder
    Module.put_attribute(__CALLER__.module, :ek_container_nft, false)

    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.begin_container(
          var!(ek_pod_builder),
          to_string(unquote(name)),
          unquote(opts)
        )

      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_container(var!(ek_pod_builder))
    end
  end

  @doc """
  Explicitly repeat a pod DSL block while threading the pod builder.

      for_each i <- 0..2 do
        container "web-\#{i}",
          binary: "/opt/web",
          zone: "net",
          restart: :permanent
      end

  Use this instead of `replicas:` when the stack should show every
  instance name and per-instance option.
  """
  defmacro for_each({:<-, _, [var, enumerable]}, do: block) do
    quote do
      var!(ek_pod_builder) =
        Enum.reduce(unquote(enumerable), var!(ek_pod_builder), fn unquote(var), ek_pod_builder ->
          var!(ek_pod_builder) = ek_pod_builder
          unquote(block)
          var!(ek_pod_builder)
        end)
    end
  end

  @doc """
  Declare a service-capability requirement for the enclosing container.

  ## Example

      container "api", binary: "/opt/bin/api", zone: "containers", ... do
        requires :"dns.local"          # network capability — declarative
        requires :"journal.local"      # socket capability — auto-mount + env

        nft do
          # ...
        end
      end

  Behaviour follows `Erlkoenig.Capabilities.fetch!/1`:

    * `:socket`-kind capabilities pull in a directory bind-mount of
      `/run/erlkoenig/` and inject the per-capability env var
      pointing at the in-container socket path.
    * `:network`-kind capabilities are recorded in `:requires` only;
      the runtime configures the network path (e.g. `/etc/resolv.conf`
      for DNS) regardless of declaration.

  Operators reading the stack file see at a glance which workloads
  depend on which node-local services. Unknown capability names
  raise at compile time.
  """
  defmacro requires(capability) do
    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.add_requires(var!(ek_pod_builder), unquote(capability), [])
    end
  end

  @doc """
  `conn_limit/1` — bound the concurrent connection count keyed by
  source IP. SPEC-EK-028 Tracker column #1.

  **Chain-scoped.** Must appear INSIDE an `nft do input ... end`
  (container-inline form) or an `nft_table ... base_chain ...`
  block (host/table form). This keeps Glasbox: the rule shows up in
  the nft chain exactly where the operator placed it, including
  policy and ordering. Zero auto-synthesis.

  Compiles to a single `connlimit_drop` nft rule: `ct count over N
  saddr drop` — matching the kernel when the source's concurrent
  conntrack count exceeds `N`.

  ## Options

  | Option | Type | Required | Description |
  |--------|------|----------|-------------|
  | `per_ip:` | integer | yes | Cap concurrent connections per source IP |

  ## Example

      container "api", binary: "/opt/bin/api" do
        nft do
          input policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, tcp_dport: 8080
            conn_limit per_ip: 100
          end
        end
      end

  The `conn_limit` line is visible in the input chain next to the
  other accept rules. An operator running `ek inspect nft <ct>`
  sees the generated `ct count over 100 saddr drop` line right
  where the DSL placed it.

  ## What this does NOT do

  * No per-rejection audit-chain event in phase 1 — that needs
    cross-netns NFLOG dispatch (SPEC-EK-028 §8bis, phase 1-bis).
  * No global (unkeyed) variant — `global:` was removed from the
    spec after review: the kernel's `listen()` backlog already
    provides per-container total-conn backpressure, so a second
    nft-layer cap was ceremony. Re-add when a real use case
    surfaces.
  """
  defmacro conn_limit(opts) do
    if Module.get_attribute(__CALLER__.module, :ek_container_nft) do
      quote do
        var!(ek_pod_builder) =
          Erlkoenig.Pod.Builder.add_conn_limit(
            var!(ek_pod_builder),
            unquote(opts)
          )
      end
    else
      quote do
        var!(ek_nft_chain) =
          Erlkoenig.Nft.ChainBuilder.add_conn_limit(
            var!(ek_nft_chain),
            unquote(opts)
          )
      end
    end
  end

  @doc """
  `requires/2` — declare a capability with options.

  Used by capabilities whose injection is parameterised. Today only
  `:"dns.allowlist"` consumes opts (`hosts: [...]`); other capabilities
  accept and ignore opts.
  """
  defmacro requires(capability, opts) do
    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.add_requires(
          var!(ek_pod_builder),
          unquote(capability),
          unquote(opts)
        )
    end
  end

  # ═══════════════════════════════════════════════════════════
  # volume — persistent bind-mount directories
  # ═══════════════════════════════════════════════════════════

  @doc """
  Declare a bind-mount volume for the enclosing container.

  The host-side storage is managed centrally by erlkoenig under a
  UUID-based path (`/var/lib/erlkoenig/volumes/<uuid>/`); the DSL
  only picks a logical *persist name* and the container-side mount
  point. The `<uuid> ↔ (container, persist)` mapping lives in the
  volume metadata store (`erlkoenig_volume_store`).

  ## Options

    * `:persist` — (required) logical store name, `[a-z0-9][a-z0-9_-]*`.
      Stable across container restarts: the same `(container, persist)`
      pair always resolves to the same UUID.
    * `:read_only` — legacy boolean shortcut for `opts: "ro"`.
    * `:opts` — mount-options string in `mount(8)` syntax, parsed
      at config-load time via `erlkoenig_mount_opts:parse/1`. Typos
      raise at compile time. Takes precedence over `:read_only`.
    * `:ephemeral` — if `true`, the volume is destroyed when the
      container enters the `stopped` or `failed` state. Default is
      `false` (persistent): data survives container destroy and must
      be removed explicitly. Use `true` for scratch space, per-run
      caches, and test containers.
    * `:quota` — hard byte limit, enforced via XFS project quota.
      Accepts a binary with a size suffix (`"1G"`, `"500M"`, `"2T"`),
      a plain integer (bytes), or `0`/omitted for no quota. Requires
      the volumes FS to be mounted with `prjquota`; if `xfs_quota`
      is missing or the mount doesn't support it the limit is stored
      in metadata but not enforced (logged as a warning).

  ## Examples

      container "app", binary: "/opt/app", zone: "dmz",
        replicas: 1, restart: :permanent do

        # Persistent — survives container destroy
        volume "/data",    persist: "app-data"

        # Read-only config
        volume "/etc/app", persist: "app-config", read_only: true

        # Hardened persistent volume with a hard disk budget
        volume "/uploads", persist: "app-uploads",
                           opts: "rw,nosuid,nodev,noexec,relatime",
                           quota: "5G"

        # Ephemeral scratch — gone when the container dies
        volume "/scratch", persist: "scratch",
                           ephemeral: true
      end
  """
  defmacro volume(container_path, opts) do
    quote do
      persist_name = Keyword.fetch!(unquote(opts), :persist)
      read_only = Keyword.get(unquote(opts), :read_only, false)
      mount_opts = Keyword.get(unquote(opts), :opts)
      ephemeral = Keyword.get(unquote(opts), :ephemeral, false)
      quota = Keyword.get(unquote(opts), :quota)

      unless is_boolean(ephemeral) do
        raise ArgumentError,
              "volume ephemeral: expected a boolean, got #{inspect(ephemeral)}"
      end

      entry = %{
        container: unquote(container_path),
        persist: persist_name,
        read_only: read_only,
        ephemeral: ephemeral
      }

      entry =
        case mount_opts do
          nil ->
            entry

          s when is_binary(s) ->
            Map.put(entry, :opts, s)

          other ->
            raise ArgumentError,
                  "volume opts: expected a binary string, got #{inspect(other)}"
        end

      entry =
        case quota do
          nil ->
            entry

          q when is_binary(q) ->
            Map.put(entry, :quota, q)

          q when is_integer(q) and q >= 0 ->
            Map.put(entry, :quota, q)

          other ->
            raise ArgumentError,
                  "volume quota: expected a size string (\"1G\") or non-negative integer, got #{inspect(other)}"
        end

      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.add_volume(
          var!(ek_pod_builder),
          entry
        )
    end
  end

  # ═══════════════════════════════════════════════════════════
  # publish — container stats collection (SPEC-EK-007)
  # ═══════════════════════════════════════════════════════════

  @doc """
  Configure periodic cgroup metrics publishing for a container.

  Each `publish` block creates a timer that reads selected cgroup metrics
  at the specified interval and publishes them as AMQP events via
  `erlkoenig_events:notify/1`.

  Multiple `publish` blocks per container are allowed — use different
  intervals for fast metrics (memory/cpu) vs. slow metrics (pressure/oom).

  Without any `publish` block, no stats events are emitted (opt-in).

  ## Options

  | Option | Type | Constraint | Description |
  |--------|------|------------|-------------|
  | `interval:` | `integer` | >= 1000 | Polling interval in milliseconds |

  ## AMQP Routing Keys

  Each metric produces a separate event: `stats.<container-name>.<metric>`

  - `stats.web-0-nginx.memory` — memory usage
  - `stats.web-0-nginx.cpu` — CPU time
  - `stats.web-0-nginx.pids` — process count
  - `stats.web-0-nginx.pressure` — PSI stall information
  - `stats.web-0-nginx.oom` — OOM kill events

  ## Examples

      # Fast metrics every 2 seconds
      publish interval: 2000 do
        metric :memory
        metric :cpu
        metric :pids
      end

      # Slow metrics every 30 seconds
      publish interval: 30_000 do
        metric :pressure
        metric :oom_events
      end
  """
  defmacro publish(opts, do: block) do
    interval = Keyword.fetch!(opts, :interval)

    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.begin_publish(
          var!(ek_pod_builder),
          unquote(interval)
        )

      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_publish(var!(ek_pod_builder))
    end
  end

  @doc """
  Select a cgroup metric for publishing. Must be inside a `publish` block.

  ## Available Metrics

  | Metric | cgroup Files | Payload Fields |
  |--------|-------------|----------------|
  | `:memory` | `memory.current`, `memory.peak`, `memory.max`, `memory.swap.current` | `current`, `peak`, `max`, `pct`, `swap` |
  | `:cpu` | `cpu.stat` | `usec`, `delta_usec`, `throttled_usec`, `nr_throttled` |
  | `:pids` | `pids.current`, `pids.max` | `current`, `max` |
  | `:pressure` | `cpu.pressure`, `memory.pressure`, `io.pressure` | `cpu_some_avg10`, `memory_some_avg10`, `io_some_avg10` |
  | `:oom_events` | `memory.events` | `kills`, `events`, `high`, `max` |

  ## Computed Fields

  - `memory.pct` = `current / max * 100` (0.0 if max is unlimited)
  - `cpu.delta_usec` = difference since last poll (useful for rate calculation)
  """
  defmacro metric(name) do
    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.add_metric(
          var!(ek_pod_builder),
          unquote(name)
        )
    end
  end

  # ═══════════════════════════════════════════════════════════
  # stream — container log streaming (SPEC-EK-011)
  # ═══════════════════════════════════════════════════════════

  @doc """
  Configure log streaming for a container via RabbitMQ Streams.

  stdout and stderr land in a single append-only RabbitMQ Stream per
  container. Retention is a stream-level property — both channels
  share the same retention.

  ## Options

  | Option | Type | Default | Description |
  |--------|------|---------|-------------|
  | `retention:` | `{integer, :days}` | `{7, :days}` | How long data stays in the stream |
  | `max_bytes:` | `{number, :gb \\| :mb}` | unlimited | Optional size cap |

  ## Contains

  - `channel :stdout` — stream container stdout
  - `channel :stderr` — stream container stderr

  Without a `stream` block, no log streaming occurs (like today).

  ## Examples

      # Stream both channels, 90 day retention
      stream retention: {90, :days} do
        channel :stdout
        channel :stderr
      end

      # stderr only, with size cap
      stream retention: {30, :days}, max_bytes: {5, :gb} do
        channel :stderr
      end
  """
  defmacro stream(do: block) do
    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.begin_stream(
          var!(ek_pod_builder),
          []
        )

      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_stream(var!(ek_pod_builder))
    end
  end

  @doc "Open a log stream block with options (e.g. `retention: {30, :days}`)."
  defmacro stream(opts, do: block) do
    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.begin_stream(
          var!(ek_pod_builder),
          unquote(opts)
        )

      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_stream(var!(ek_pod_builder))
    end
  end

  @doc """
  Select a channel for log streaming. Must be inside a `stream` block.

  Available channels: `:stdout`, `:stderr`.
  """
  defmacro channel(name) do
    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.add_channel(
          var!(ek_pod_builder),
          unquote(name)
        )
    end
  end
end
