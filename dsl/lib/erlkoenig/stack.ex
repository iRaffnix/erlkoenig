defmodule Erlkoenig.Stack do
  @moduledoc """
  Unified DSL for the erlkoenig ecosystem.

  Topology and policy in one file, readable by network engineers. One
  `pod` is the **logical bracket** around all containers that belong
  together; each container declares its own `zone:` and `replicas:`
  inline — there is no separate `attach` step.

      defmodule MyInfra do
        use Erlkoenig.Stack

        host do
          ipvlan "dmz", parent: {:device, "eth0"}, subnet: {10, 0, 0, 0, 24}

          nft_table :inet, "host" do
            base_chain "input", hook: :input, type: :filter,
              priority: :filter, policy: :drop do
              nft_rule :accept, ct_state: [:established, :related]
              nft_rule :drop
            end
          end
        end

        pod "web", strategy: :one_for_one do
          container "frontend",
            binary: "/opt/frontend",
            zone: "dmz",
            replicas: 3,
            restart: :permanent do
            nft do
              output do
                nft_rule :accept, ct_state: [:established, :related]
                nft_rule :drop
              end
            end
          end
        end
      end

  ## Required options (nothing implicit)

  - `pod`: `strategy:`
  - `container`: `binary:`, `zone:`, `replicas:`, `restart:`

  Other options have documented defaults.

  ## Naming in rules

  Interface names used in `iifname:`/`oifname:` rules reference host-level
  interfaces only (`"eth0"`, `"lo"`). Container slaves live inside their
  own netns and are never visible on the host — match them by **IP**
  (`ip_saddr:`/`ip_daddr:`) instead.
  """

  defmacro __using__(_opts) do
    quote do
      import Erlkoenig.Stack
      import Erlkoenig.TimeUnits

      Module.register_attribute(__MODULE__, :stack_host, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_pods, accumulate: true)
      Module.register_attribute(__MODULE__, :stack_guard, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_watches, accumulate: true)
      Module.register_attribute(__MODULE__, :stack_nft_tables, accumulate: true)

      Module.put_attribute(__MODULE__, :stack_host, nil)
      Module.put_attribute(__MODULE__, :stack_guard, nil)
      Module.register_attribute(__MODULE__, :ek_container_nft, accumulate: false)
      Module.put_attribute(__MODULE__, :ek_container_nft, false)

      @before_compile Erlkoenig.Stack
    end
  end

  defmacro __before_compile__(env) do
    host = Module.get_attribute(env.module, :stack_host)
    pods = Module.get_attribute(env.module, :stack_pods) |> Enum.reverse()
    guard_config = Module.get_attribute(env.module, :stack_guard)
    watches = Module.get_attribute(env.module, :stack_watches) |> Enum.reverse()

    # Validate pods
    Enum.each(pods, &Erlkoenig.Pod.Builder.validate!/1)

    Erlkoenig.Validation.check_uniqueness(pods, :name, "pod names")
    pod_names = Enum.map(pods, & &1.name)

    # Build list of all container names (pod-qualified)
    all_container_names = Enum.flat_map(pods, fn pod ->
      Enum.map(pod.containers, fn ct ->
        "#{pod.name}.#{ct.name}"
      end)
    end)

    # Validate host
    if host do
      Erlkoenig.Host.Builder.validate!(host, pod_names, all_container_names)
    end

    # Validate each container's `zone:` references a declared ipvlan zone
    zone_names = if host, do: Enum.map(host.ipvlans, & &1.name), else: []
    Enum.each(pods, fn pod ->
      Enum.each(pod.containers, fn ct ->
        unless ct.zone in zone_names do
          raise CompileError,
            description: "container #{inspect(pod.name)}/#{inspect(ct.name)}: " <>
              "zone #{inspect(ct.zone)} is not declared by any `ipvlan`. " <>
              "Known zones: #{inspect(zone_names)}"
        end
      end)
    end)

    # Build term
    pods_term = Enum.map(pods, &Erlkoenig.Pod.Builder.to_term/1)

    # Each ipvlan becomes a zone. Zones no longer carry `deployments` —
    # each container inside a pod carries its own `zone:` + `replicas:`.
    zones_term = if host do
      Enum.map(host.ipvlans, fn ipv ->
        zone = %{
          name: ipv.name,
          subnet: ipv.subnet,
          netmask: ipv.netmask,
          network: %{mode: :ipvlan, parent: ipv.parent,
                     parent_type: ipv.parent_type,
                     ipvlan_mode: ipv.ipvlan_mode},
          pool: %{start: put_elem(ipv.subnet, 3, 2),
                  stop: put_elem(ipv.subnet, 3, 254)}
        }
        if ipv.gateway, do: put_in(zone, [:network, :gateway], ipv.gateway), else: zone
      end)
    else
      []
    end

    # Build base term (no legacy firewall — ADR-0015)
    term = %{}
    term = if host, do: Map.put(term, :host, Erlkoenig.Host.Builder.to_term(host)), else: term
    term = if pods_term != [], do: Map.put(term, :pods, pods_term), else: term
    term = if zones_term != [], do: Map.put(term, :zones, zones_term), else: term
    # Validate and build nft_tables
    nft_tables = Module.get_attribute(env.module, :stack_nft_tables) |> Enum.reverse()
    Enum.each(nft_tables, &Erlkoenig.Nft.TableBuilder.validate!/1)

    # Check table name uniqueness
    Erlkoenig.Validation.check_uniqueness(nft_tables, :name, "nft_table names")

    nft_tables_term = Enum.map(nft_tables, &Erlkoenig.Nft.TableBuilder.to_term/1)

    term = if guard_config, do: Map.put(term, :ct_guard, guard_config), else: term
    term = if watches != [], do: Map.put(term, :watch, hd(watches)), else: term
    term = if nft_tables_term != [], do: Map.put(term, :nft_tables, nft_tables_term), else: term

    quote do
      def config, do: unquote(Macro.escape(term))

      def write!(path) do
        formatted = :io_lib.format(~c"~tp.~n", [config()])
        File.write!(path, formatted)
      end
    end
  end

  # ═══════════════════════════════════════════════════════════
  # host — the machine, its interfaces, IPVLAN zones, firewall
  # ═══════════════════════════════════════════════════════════

  @doc """
  Define the host machine — its interfaces, IPVLAN zones, and firewall tables.

  The `host` block is the top-level physical machine configuration.
  Everything inside describes what the host looks like *before* any
  containers are deployed: which network interfaces exist, which
  IPVLAN zones to create, and which nft tables to apply.

  There can be at most one `host` block per stack.

  ## Contains

  - `interface` — physical network interfaces
  - `ipvlan` — IPVLAN L3S zones (parent device + subnet — container
    slaves are placed directly into container netns)
  - `nft_table` — firewall tables (can also be outside `host`)

  ## Examples

      host do
        interface "eth0", zone: :wan
        interface "eth1", zone: :lan
        ipvlan "dmz",  parent: {:device, "eth0"},    subnet: {10, 0, 0, 0, 24}
        ipvlan "app",  parent: {:dummy,  "ek_app"},  subnet: {10, 0, 1, 0, 24}
        ipvlan "data", parent: {:dummy,  "ek_data"}, subnet: {10, 0, 2, 0, 24}
      end
  """
  defmacro host(do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :host)

    quote do
      var!(ek_host_builder) = Erlkoenig.Host.Builder.new()
      unquote(block)
      @stack_host var!(ek_host_builder)
    end
  end

  @doc """
  Declare a physical network interface on the host.

  Interfaces are informational — they tell the DSL which physical
  NICs exist and what zone they belong to. Zone labels are used in
  nft rules (e.g. `iifname: "eth0"`) and to pick IPVLAN parent devices.

  ## Options

  | Option | Type | Default | Description |
  |--------|------|---------|-------------|
  | `zone:` | atom | none | Zone classification: `:wan`, `:lan`, `:dmz`, etc. |

  ## Examples

      host do
        interface "eth0", zone: :wan    # internet-facing
        interface "eth1", zone: :lan    # internal network
        interface "lo"                  # loopback (no zone)
      end
  """
  defmacro interface(name, opts \\ []) do
    quote do
      var!(ek_host_builder) = Erlkoenig.Host.Builder.add_interface(
        var!(ek_host_builder), unquote(name), unquote(opts))
    end
  end

  @doc """
  Declare an IPVLAN network segment on the host.

  Creates IPVLAN L3S slaves for containers. This is the only networking
  mode since ADR-0020 — there is no bridge/veth path.

  ## Options

    * `:parent` — (required) `{:device, "eth0"}` to attach to a physical
      host interface, or `{:dummy, "ek_<name>"}` to have erlkoenig create
      and own a kernel `dummy0` parent. Bare strings are rejected at
      compile time.
    * `:subnet` — (required) `{a, b, c, d, mask}` (only `/24` supported
      today) or `{a, b, c, d}` (defaults to `/24`).
    * `:mode` — `:l3s` (default), `:l3`, or `:l2`.
    * `:gateway` — optional gateway IP. Only meaningful for `{:dummy, ...}`
      parents (erlkoenig assigns it onto the dummy so containers can reach
      DNS etc. locally).

  ## Example

      host do
        interface "eth0"
        ipvlan "edge",  parent: {:device, "eth0"},    subnet: {10, 20, 0, 0, 24}
        ipvlan "inner", parent: {:dummy,  "ek_inner"}, subnet: {10, 40, 0, 0, 24}
      end
  """
  defmacro ipvlan(name, opts) do
    quote do
      var!(ek_host_builder) = Erlkoenig.Host.Builder.add_ipvlan(
        var!(ek_host_builder), unquote(name), unquote(opts))
    end
  end

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
      description: "pod #{inspect(name)}: strategy: is required " <>
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
  | `replicas:` | `pos_integer` | How many container instances to spawn |
  | `restart:` | `:permanent` \\| `:transient` \\| `:temporary` | OTP restart policy |

  ## Optional Options (with sensible defaults)

  | Option | Type | Default | Description |
  |--------|------|---------|-------------|
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
        zone: "net", replicas: 1, restart: :permanent

      # With cgroup metrics publishing
      container "nginx",
        binary: "/opt/nginx", args: ["8443"],
        zone: "dmz", replicas: 3, restart: :permanent do
        publish interval: 2000 do
          metric :memory
          metric :cpu
          metric :pids
        end
      end
  """
  defmacro container(name, opts) when is_list(opts) do
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_container(
        var!(ek_pod_builder), unquote(to_string(name)), unquote(opts))
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_container(
        var!(ek_pod_builder))
    end
  end

  defmacro container(name, opts, do: block) when is_list(opts) do
    # Reset container nft context after expansion so host nft_rules
    # in nft_table blocks don't dispatch to the pod builder
    Module.put_attribute(__CALLER__.module, :ek_container_nft, false)
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_container(
        var!(ek_pod_builder), unquote(to_string(name)), unquote(opts))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_container(
        var!(ek_pod_builder))
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

  ## Examples

      container "app", binary: "/opt/app", zone: "dmz",
        replicas: 1, restart: :permanent do

        # Persistent — survives container destroy
        volume "/data",    persist: "app-data"

        # Read-only config
        volume "/etc/app", persist: "app-config", read_only: true

        # Hardened persistent volume
        volume "/uploads", persist: "app-uploads",
                           opts: "rw,nosuid,nodev,noexec,relatime"

        # Ephemeral scratch — gone when the container dies
        volume "/scratch", persist: "scratch",
                           ephemeral: true
      end
  """
  defmacro volume(container_path, opts) do
    quote do
      persist_name = Keyword.fetch!(unquote(opts), :persist)
      read_only    = Keyword.get(unquote(opts), :read_only, false)
      mount_opts   = Keyword.get(unquote(opts), :opts)
      ephemeral    = Keyword.get(unquote(opts), :ephemeral, false)

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

      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.add_volume(
        var!(ek_pod_builder), entry)
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
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_publish(
        var!(ek_pod_builder), unquote(interval))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_publish(
        var!(ek_pod_builder))
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
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.add_metric(
        var!(ek_pod_builder), unquote(name))
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
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_stream(
        var!(ek_pod_builder), [])
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_stream(
        var!(ek_pod_builder))
    end
  end

  @doc "Open a log stream block with options (e.g. `retention: {30, :days}`)."
  defmacro stream(opts, do: block) do
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_stream(
        var!(ek_pod_builder), unquote(opts))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_stream(
        var!(ek_pod_builder))
    end
  end

  @doc """
  Select a channel for log streaming. Must be inside a `stream` block.

  Available channels: `:stdout`, `:stderr`.
  """
  defmacro channel(name) do
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.add_channel(
        var!(ek_pod_builder), unquote(name))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # nft — per-container firewall (SPEC-EK-023)
  # ═══════════════════════════════════════════════════════════

  @doc """
  Define nftables firewall rules for this container.

  Rules are installed inside the container's network namespace via
  CMD_NFT_SETUP. Must be inside a `container` block with a `do` body.

  Contains `output` and `input` sub-blocks that map to nft base chains
  with the respective hooks.

  ## Example

      container "api", binary: "/opt/api", restart: :permanent do
        nft do
          output policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, iifname: "lo"
            nft_rule :accept, tcp_dport: 5432
          end
          input policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, iifname: "lo"
            nft_rule :accept, tcp_dport: 4000
          end
        end
      end
  """
  defmacro nft(do: block) do
    Module.put_attribute(__CALLER__.module, :ek_container_nft, true)
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_nft(
        var!(ek_pod_builder))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_nft(
        var!(ek_pod_builder))
    end
  end

  @doc "Define an OUTPUT chain inside an `nft` block."
  defmacro output(opts, do: block) do
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_nft_chain(
        var!(ek_pod_builder), :output, unquote(opts))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_nft_chain(
        var!(ek_pod_builder))
    end
  end

  @doc "Define an INPUT chain inside an `nft` block."
  defmacro input(opts, do: block) do
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_nft_chain(
        var!(ek_pod_builder), :input, unquote(opts))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_nft_chain(
        var!(ek_pod_builder))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # OLD SYNTAX REMOVED (ADR-0015: harter Bruch)
  #
  # The following macros were removed:
  #   chain/3      — use nft_table + base_chain/nft_chain instead
  #   rule/2       — use nft_rule instead (with nft field names)
  #   counters/1   — use nft_counter inside nft_table instead
  #   set/3        — not yet reimplemented
  #
  # Old field names:
  #   tcp: 8443    → tcp_dport: 8443
  #   iif: "eth0"  → iifname: "eth0"
  #   oif: "eth0"  → oifname: "eth0"
  #   ct: :established → ct_state: [:established, :related]
  #   log: "DROP:" → log_prefix: "DROP:"
  # ═══════════════════════════════════════════════════════════

  # ═══════════════════════════════════════════════════════════
  # guard / watch — Erlang runtime
  # ═══════════════════════════════════════════════════════════

  @doc """
  Configure the reactive threat detection guard.

  Each suspicious source IP gets its own Erlang process
  (`erlkoenig_threat_actor`, gen_statem) with a lifecycle:

      observing → suspicious → banned → probation → (process dies)

  Actors detect floods, port scans, slow scans, and honeypot probes.
  Ban decisions flow through `erlkoenig_threat_mesh` — the single
  process that writes to the kernel blocklist. Kernel bans have
  built-in timeouts and auto-expire even if the BEAM crashes.

  ## Structure

  Three blocks — what we detect, how we respond, who we exempt:

  ## Examples

      guard do
        detect do
          flood over: 50, within: s(10)
          port_scan over: 20, within: m(1)
          slow_scan over: 5, within: h(1)
          honeypot [21, 22, 23, 445, 1433, 1521, 3306,
                    3389, 5900, 6379, 8080, 8888, 9200, 27017]
        end

        respond do
          suspect after: 3, distinct: :ports
          ban_for h(1)
          honeypot_ban_for h(24)
          escalate [h(1), h(6), h(24), d(7)]
          observe_after_unban m(2)
          forget_after m(5)
        end

        allowlist [
          {127, 0, 0, 1},
          {10, 0, 0, 1}
        ]
      end
  """
  defmacro guard(do: block) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.new()
      unquote(block)
      @stack_guard ErlkoenigNft.Guard.Builder.to_term(var!(ek_guard_builder))
    end
  end

  # ── detect block ──────────────────────────────────────

  @doc "Open the detection block. Contains `flood`, `port_scan`, `slow_scan`, `honeypot`."
  defmacro detect(do: block) do
    quote do
      unquote(block)
    end
  end

  @doc "Detect connection floods: too many connections from one IP."
  defmacro flood(opts) do
    over = Keyword.fetch!(opts, :over)
    within = Keyword.fetch!(opts, :within)
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.add_flood(
        var!(ek_guard_builder), unquote(over), unquote(within))
    end
  end

  @doc "Detect port scans: too many distinct destination ports from one IP."
  defmacro port_scan(opts) do
    over = Keyword.fetch!(opts, :over)
    within = Keyword.fetch!(opts, :within)
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.add_port_scan(
        var!(ek_guard_builder), unquote(over), unquote(within))
    end
  end

  @doc "Detect slow scans: distinct ports over a long window."
  defmacro slow_scan(opts) do
    over = Keyword.fetch!(opts, :over)
    within = Keyword.fetch!(opts, :within)
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.add_slow_scan(
        var!(ek_guard_builder), unquote(over), unquote(within))
    end
  end

  @doc "Honeypot ports: any connection triggers instant ban."
  defmacro honeypot(ports) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_honeypot_ports(
        var!(ek_guard_builder), unquote(ports))
    end
  end

  # ── respond block ─────────────────────────────────────

  @doc "Open the response block. Defines what happens when a threat is detected."
  defmacro respond(do: block) do
    quote do
      unquote(block)
    end
  end

  @doc "Mark IP as suspicious after N distinct ports contacted."
  defmacro suspect(opts) do
    after_count = Keyword.fetch!(opts, :after)
    by = Keyword.get(opts, :distinct, :ports)
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_suspect(
        var!(ek_guard_builder), unquote(after_count), unquote(by))
    end
  end

  @doc "Default ban duration."
  defmacro ban_for(seconds) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_ban_duration(
        var!(ek_guard_builder), unquote(seconds))
    end
  end

  @doc "Ban duration for honeypot triggers."
  defmacro honeypot_ban_for(seconds) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_honeypot_ban_duration(
        var!(ek_guard_builder), unquote(seconds))
    end
  end

  @doc "Escalating ban durations for repeat offenders."
  defmacro escalate(durations) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_escalation(
        var!(ek_guard_builder), unquote(durations))
    end
  end

  @doc "Observation period after unban before the IP is forgotten."
  defmacro observe_after_unban(seconds) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_probation(
        var!(ek_guard_builder), unquote(seconds))
    end
  end

  @doc "Forget an IP after this many seconds without events."
  defmacro forget_after(seconds) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_forget_after(
        var!(ek_guard_builder), unquote(seconds))
    end
  end

  # ── allowlist ─────────────────────────────────────────

  @doc "IPs that are never banned, regardless of behavior."
  defmacro allowlist(ips) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_allowlist(
        var!(ek_guard_builder), unquote(ips))
    end
  end

  @doc """
  Configure a conntrack/nflog watcher.

  Watchers subscribe to kernel events (connection tracking, logged packets)
  and forward them to the erlkoenig event bus for AMQP publishing.

  ## Examples

      watch "connections" do
        # watcher configuration
      end
  """
  defmacro watch(name, do: block) do
    quote do
      var!(ek_watch_builder) = ErlkoenigNft.Watch.Builder.new(unquote(name))
      unquote(block)
      @stack_watches ErlkoenigNft.Watch.Builder.to_term(var!(ek_watch_builder))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # nft_table / base_chain / chain — nft-transparent DSL (ADR-0015)
  # ═══════════════════════════════════════════════════════════

  @doc """
  Define an nftables table — the top-level container for chains, counters, sets, and vmaps.

  Tables are the foundation of the nft-transparent DSL (ADR-0015). Each table
  maps 1:1 to a real nftables table. Multiple tables per stack are allowed
  (e.g. one for host protection, one for container firewall).

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `family` | `:inet` \\| `:ip` \\| `:ip6` | Address family. `:inet` handles both IPv4 and IPv6 |
  | `name` | `string` | Table name (e.g. `"host"`, `"erlkoenig"`, `"filter"`) |

  ## Contains

  - `base_chain` — chain attached to a netfilter hook
  - `nft_chain` — regular chain (jump target)
  - `nft_counter` — named counter object
  - `nft_set` — named set (IP blocklists, etc.)
  - `nft_vmap` — verdict map for dispatch

  ## Validation

  - Table must contain at least one chain → `CompileError`
  - Duplicate table names in one stack → `CompileError`
  - Duplicate chain names within a table → `CompileError`
  - Counter referenced in rules must be declared → `CompileError`

  ## Examples

      # Host firewall
      nft_table :inet, "host" do
        base_chain "input", hook: :input, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, iifname: "lo"
          nft_rule :accept, tcp_dport: 22
        end
      end

      # Container firewall with counters and IP-based dispatch
      nft_table :inet, "erlkoenig" do
        nft_counter "forward_drop"

        base_chain "forward", hook: :forward, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :jump,
            ip_saddr: {:replica_ips, "web", "nginx"}, to: "from-web"
          nft_rule :drop, counter: "forward_drop"
        end

        nft_chain "from-web" do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :drop
        end
      end
  """
  defmacro nft_table(family, name, do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :nft_table)

    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.new(unquote(family), unquote(name))
      unquote(block)
      @stack_nft_tables var!(ek_nft_table)
    end
  end

  @doc """
  Define a base chain — attached to a netfilter hook.

  A base chain is an entry point into the firewall. The kernel delivers
  packets to the chain based on the hook point. In contrast to `nft_chain`
  (regular chain), which is only entered via `:jump` rules.

  Syntax: `base_chain "name", hook: ..., type: ..., priority: ..., policy: ... do ... end`

  The four parameters determine **when** (hook), **what it can do** (type),
  **in which order** (priority), and **what happens when nothing matches** (policy).

  ## Options

  ### `hook:` — when does this chain see packets

  | Hook | Packets | Typical use |
  |------|---------|-------------|
  | `:input` | Destined for the host itself | Host firewall (SSH, ICMP) |
  | `:forward` | Routed through the host (container ↔ container) | Container firewall |
  | `:output` | Sent by the host itself | Outbound restrictions |
  | `:prerouting` | All incoming, before routing decision | Ban sets (raw), DNAT |
  | `:postrouting` | All outgoing, after routing decision | SNAT, Masquerade |

  ### `type:` — what can the chain do

  | Type | Allowed actions | Typical with |
  |------|----------------|--------------|
  | `:filter` | accept, drop, jump, reject | input, forward, output, prerouting |
  | `:nat` | snat, dnat, masquerade, redirect | prerouting (dnat), postrouting (snat) |
  | `:route` | Mark-based rerouting | output |

  ### `priority:` — evaluation order (lower = earlier)

  | Priority | Value | When |
  |----------|-------|------|
  | `:raw` | -300 | Before conntrack — ban sets go here |
  | `:mangle` | -150 | Before filter — packet manipulation |
  | `:dstnat` | -100 | DNAT (port forwarding) |
  | `:filter` | 0 | Standard filtering |
  | `:security` | 50 | After filter — SELinux |
  | `:srcnat` | 100 | SNAT/Masquerade (after routing) |

  An integer can also be used directly (e.g. `priority: -200`).

  ### `policy:` — default verdict

  | Policy | Meaning |
  |--------|---------|
  | `:drop` | Drop everything that doesn't match a rule (secure, deny-by-default) |
  | `:accept` | Accept everything that doesn't match (open, use for NAT chains) |

  ## Common Combinations

  | Use Case | hook | type | priority | policy |
  |----------|------|------|----------|--------|
  | Host firewall | `:input` | `:filter` | `:filter` | `:drop` |
  | Container firewall | `:forward` | `:filter` | `:filter` | `:drop` |
  | Ban before conntrack | `:prerouting` | `:filter` | `:raw` | `:accept` |
  | Port forwarding (DNAT) | `:prerouting` | `:nat` | `:dstnat` | `:accept` |
  | Masquerade (SNAT) | `:postrouting` | `:nat` | `:srcnat` | `:accept` |

  ## Examples

      # Ban set in raw priority — before conntrack, zero kernel state
      base_chain "prerouting", hook: :prerouting, type: :filter,
        priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      # Host input firewall — deny by default
      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop, counter: "input_drop", log_prefix: "HOST: "
      end

      # Container forward firewall — deny by default
      base_chain "forward", hook: :forward, type: :filter,
        priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :jump,
          ip_saddr: {:replica_ips, "web", "nginx"}, to: "from-web"
        nft_rule :drop, counter: "forward_drop"
      end

      # NAT: masquerade container traffic leaving the host
      base_chain "postrouting", hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do
        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "eth0"
      end
  """
  defmacro base_chain(name, opts, do: block) do
    Module.put_attribute(__CALLER__.module, :ek_container_nft, false)
    quote do
      var!(ek_nft_chain) = Erlkoenig.Nft.ChainBuilder.new_base(unquote(name), unquote(opts))
      unquote(block)
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_chain(
        var!(ek_nft_table), var!(ek_nft_chain))
    end
  end

  # Override: chain inside nft_table context (regular chain, no hook/policy)
  # The existing chain/3 macro handles host/pod contexts via @__ek_context__
  # This version is for nft_table context only
  @doc """
  Define a regular chain — a jump target with no hook.

  Regular chains are not attached to netfilter. They are entered
  via `:jump` rules from base chains or other regular chains.
  At the end of a regular chain, execution returns to the caller
  (implicit `return`).

  Used for **egress filtering**: one chain per container that controls
  what outbound traffic the container may send.

  ## Examples

      # Egress: nginx may only connect to API on port 4000
      nft_chain "from-web-nginx" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 4000
        nft_rule :drop, counter: "nginx_drop"
      end

      # Called from forward chain via (dispatch by source IP — IPVLAN
      # slaves are not host-visible, so interface matches don't work):
      #   nft_rule :jump,
      #     ip_saddr: {:replica_ips, "web", "nginx"}, to: "from-web-nginx"
  """
  defmacro nft_chain(name, do: block) do
    Module.put_attribute(__CALLER__.module, :ek_container_nft, false)
    quote do
      var!(ek_nft_chain) = Erlkoenig.Nft.ChainBuilder.new_regular(unquote(name))
      unquote(block)
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_chain(
        var!(ek_nft_table), var!(ek_nft_chain))
    end
  end

  @doc """
  Define a single nftables rule inside a chain.

  Each `nft_rule` maps 1:1 to a real `nft add rule` command.
  Rules are evaluated top-to-bottom — first match wins.

  Syntax: `nft_rule :action, match_field: value, match_field: value, ...`

  All match fields are AND-combined — all must match for the action to fire.
  For OR logic, write separate rules.

  ## Actions (first argument)

  | Action | nft equivalent | Required opts | Description |
  |--------|---------------|---------------|-------------|
  | `:accept` | `accept` | — | Accept the packet |
  | `:drop` | `drop` | — | Silently drop the packet |
  | `:return` | `return` | — | Return to the calling chain |
  | `:jump` | `jump <chain>` | `to:` | Jump to a named chain |
  | `:reject` | `reject` | — | Drop + send ICMP unreachable |
  | `:masquerade` | `masquerade` | — | SNAT to outgoing interface IP |
  | `:snat` | `snat to <ip>` | `snat_to:` | Source NAT to fixed IP |
  | `:dnat` | `dnat to <ip[:port]>` | `dnat_to:` | Destination NAT |
  | `:notrack` | `notrack` | — | Skip connection tracking |
  | `:ct_mark_set` | `ct mark set` | `mark:` | Set conntrack mark |
  | `:ct_mark_match` | `ct mark` | `mark:` | Match conntrack mark |
  | `:fib_rpf` | `fib saddr . iif oif 0 drop` | — | Reverse path filter (BCP38) |
  | `:connlimit_drop` | `ct count over N drop` | `limit:` | Connection limit per source IP |
  | `:vmap_dispatch` | `vmap @name` | `vmap:` | Verdict map dispatch |
  | `:dnat_lb` | `dnat to jhash ip saddr mod N map {...}` | `targets:`, `port:` | Source-IP hash loadbalancing |

  ## Match Fields (keyword options, all optional, combinable)

  ### Identity (who)

  | Field | nft equivalent | Type | Example |
  |-------|---------------|------|---------|
  | `ct_state:` | `ct state` | `[atom]` | `[:established, :related]` |
  | `ip_saddr:` | `ip saddr` | `ip_tuple` \\| `{:replica_ips, pod, ct}` | `{10,0,0,0,24}` |
  | `ip_daddr:` | `ip daddr` | `ip_tuple` \\| `{:replica_ips, pod, ct}` | `{10,0,0,2}` |
  | `ip_protocol:` | `ip protocol` | `atom` | `:icmp` |

  ### Interface (where)

  | Field | nft equivalent | Type | Example |
  |-------|---------------|------|---------|
  | `iifname:` | `iifname` | `string` | `"eth0"` |
  | `oifname:` | `oifname` | `string` | `"eth0"` |
  | `oifname_ne:` | `oifname !=` | `string` | `"eth0"` |

  ### Port (what)

  | Field | nft equivalent | Type | Example |
  |-------|---------------|------|---------|
  | `tcp_dport:` | `tcp dport` | `integer` \\| `{min, max}` | `8080` or `{8000, 9000}` |
  | `udp_dport:` | `udp dport` | `integer` | `53` |
  | `set:` | `@set_name` | `string` | `"ban"` — match IP against named set |

  ### Observability

  | Field | nft equivalent | Type | Example |
  |-------|---------------|------|---------|
  | `counter:` | `counter` | `string` | `"forward_drop"` — must be declared with `nft_counter` |
  | `log_prefix:` | `log prefix` | `string` | `"FWD: "` — triggers NFLOG with packet details |

  ### Action-specific

  | Field | Used with | Type | Example |
  |-------|-----------|------|---------|
  | `to:` | `:jump` | `string` | `"from-web-nginx"` |
  | `mark:` | `:ct_mark_set`, `:ct_mark_match` | `integer` | `1` |
  | `snat_to:` | `:snat` | `ip_tuple` | `{192,168,1,1}` |
  | `dnat_to:` | `:dnat` | `ip_tuple` \\| `{ip, port}` | `{10,0,0,2, 8080}` |
  | `limit:` | `:connlimit_drop` | `integer` | `100` |
  | `vmap:` | `:vmap_dispatch` | `string` | `"dispatch"` |
  | `targets:` | `:dnat_lb` | `{:replica_ips, pod, ct}` | Loadbalancing targets |
  | `port:` | `:dnat_lb` | `integer` | DNAT destination port |

  ## Deploy-Time Symbols

  Resolved when the config is loaded, not at compile time:

  - `{:replica_ips, "pod", "container"}` — expands to the list of container
    IPs across all replicas

  With `replicas: 3`, `{:replica_ips, "web", "nginx"}` generates three
  individual nft rules — one per IP.

  (The legacy `{:veth_of, ...}` symbol is still accepted by the compiler
  for backward compatibility but produces no rules in IPVLAN mode because
  slaves are not visible on the host — use `ip_saddr:` instead.)

  ## IP Tuple Format

  - `{a, b, c, d}` — single IP (e.g. `{10, 0, 0, 2}`)
  - `{a, b, c, d, mask}` — CIDR subnet (e.g. `{10, 0, 0, 0, 24}`)

  ## Combining Fields

  All fields are AND-combined. Every field must match:

      # TCP port 443 from eth0 to a specific IP — all three must match
      nft_rule :accept,
        iifname: "eth0",
        ip_daddr: {:replica_ips, "web", "nginx"},
        tcp_dport: 443

  For OR logic, write separate rules:

      # Accept port 80 OR port 443
      nft_rule :accept, tcp_dport: 80
      nft_rule :accept, tcp_dport: 443

  ## Examples

      # Accept established connections
      nft_rule :accept, ct_state: [:established, :related]

      # Drop IPs in ban set (before conntrack in raw chain)
      nft_rule :drop, set: "ban", counter: "input_ban"

      # Accept ICMP (ping)
      nft_rule :accept, ip_protocol: :icmp

      # Accept TCP on port 443 from eth0
      nft_rule :accept, iifname: "eth0", tcp_dport: 443

      # Jump to egress chain based on source IP (IPVLAN slaves have no
      # host-visible interface — dispatch by source IP instead)
      nft_rule :jump,
        ip_saddr: {:replica_ips, "web", "nginx"}, to: "from-web-nginx"

      # Allow traffic between pods (expanded at deploy time)
      nft_rule :accept,
        ip_saddr: {:replica_ips, "web", "nginx"},
        ip_daddr: {:replica_ips, "app", "api"},
        tcp_dport: 4000

      # Drop with counter and log
      nft_rule :drop, counter: "forward_drop", log_prefix: "FWD: "

      # Masquerade container subnet (NAT)
      nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "eth0"

      # DNAT: forward port 8080 to container
      nft_rule :dnat, tcp_dport: 8080, dnat_to: {10, 0, 0, 2, 8080}

      # Reverse path filter (anti-spoofing)
      nft_rule :fib_rpf

      # Connection limit: max 100 concurrent from one IP
      nft_rule :connlimit_drop, tcp_dport: 80, limit: 100

      # Source-IP hash loadbalancing across replicas
      # jhash(ip saddr) mod N → DNAT to one of N container IPs
      # Same source IP always lands on same backend (sticky)
      nft_rule :dnat_lb,
        iifname: "eth0",
        tcp_dport: 8443,
        targets: {:replica_ips, "web", "nginx"},
        port: 8443
  """
  defmacro nft_rule(action, opts \\ []) do
    if Module.get_attribute(__CALLER__.module, :ek_container_nft) do
      quote do
        var!(ek_pod_builder) = Erlkoenig.Pod.Builder.add_nft_rule(
          var!(ek_pod_builder), unquote(action), unquote(opts))
      end
    else
      quote do
        var!(ek_nft_chain) = Erlkoenig.Nft.ChainBuilder.add_rule(
          var!(ek_nft_chain), unquote(action), unquote(opts))
      end
    end
  end

  @doc """
  Declare a named counter at table level.

  Named counters are table-level objects that track packet and byte counts.
  They must be declared before being referenced in rules via `counter:`.

  erlkoenig polls counter rates periodically and publishes them as AMQP
  events (`firewall.<chain>.drop`) when the packet rate is > 0.

  ## Validation

  - Counter referenced in `nft_rule` but not declared → `CompileError`

  ## Examples

      nft_table :inet, "erlkoenig" do
        nft_counter "forward_drop"
        nft_counter "web_nginx_drop"

        base_chain "forward", hook: :forward, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :drop, counter: "forward_drop"
        end
      end
  """
  defmacro nft_counter(name) do
    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_counter(
        var!(ek_nft_table), unquote(name))
    end
  end

  @doc """
  Declare a named set at table level.

  Sets are collections of values (IPs, ports, etc.) that can be matched
  against in rules. Used for dynamic blocklists, allowlists, and
  group-based filtering.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | `string` | Set name |
  | `type` | `atom` | Element type: `:ipv4_addr`, `:ipv6_addr`, `:inet_service` |

  ## Options

  | Option | Type | Default | Description |
  |--------|------|---------|-------------|
  | `flags:` | `[atom]` | `[]` | Set flags: `:interval`, `:timeout`, `:constant` |

  ## Examples

      nft_table :inet, "erlkoenig" do
        nft_set "blocklist", :ipv4_addr

        base_chain "input", hook: :input, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :drop, set: "blocklist"
        end
      end
  """
  defmacro nft_set(name, type, opts \\ []) do
    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_set(
        var!(ek_nft_table), unquote(name), unquote(type), unquote(opts))
    end
  end

  @doc """
  Declare a verdict map (vmap) at table level.

  Verdict maps associate keys with verdicts (accept/drop/jump). Used for
  efficient multi-target dispatch — one lookup instead of N sequential rules.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | `string` | Vmap name |
  | `type` | `atom` | Key type: `:ipv4_addr`, `:inet_service`, etc. |
  | `entries` | `[{key, action}]` | Static entries: `[{{10,0,0,2}, :accept}]` |

  ## Examples

      nft_table :inet, "erlkoenig" do
        nft_vmap "dispatch", :ipv4_addr, [
          {{10, 0, 0, 2}, {:jump, "handle-web"}},
          {{10, 0, 0, 3}, {:jump, "handle-api"}}
        ]

        base_chain "forward", hook: :forward, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :vmap_dispatch, vmap: "dispatch"
        end
      end
  """
  defmacro nft_vmap(name, type, entries) do
    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_vmap(
        var!(ek_nft_table), unquote(name), unquote(type), unquote(entries))
    end
  end

  @doc """
  Declare a named data map at table level.

  Data maps associate keys with data values (not verdicts). Used for
  jhash loadbalancing: hash result (integer) → container IP.

  The developer explicitly defines the map and its entries. No implicit
  map creation — what you write is what the kernel gets.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | `string` | Map name (e.g., `"web_jhash"`) |
  | `key_type` | `atom` | Key type: `:mark`, `:ipv4_addr`, etc. |
  | `data_type` | `atom` | Value type: `:ipv4_addr`, `:inet_service`, etc. |
  | `entries` | `list` | Static entries or `{:replica_ips, pod, ct}` |

  ## Examples

      # jhash loadbalancing map
      nft_map "web_jhash", :mark, :ipv4_addr,
        entries: {:replica_ips, "web", "nginx"}

      # Rule references the map explicitly
      nft_rule :dnat_jhash,
        iifname: "eth0",
        tcp_dport: 8443,
        map: "web_jhash",
        port: 8443
  """
  defmacro nft_map(name, key_type, data_type, opts \\ []) do
    entries = Keyword.get(opts, :entries, [])
    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_map(
        var!(ek_nft_table), unquote(name), unquote(key_type),
        unquote(data_type), unquote(entries))
    end
  end

  @doc """
  Declare a concatenated verdict map at table level.

  Concat verdict maps use composite keys (e.g., ip saddr . ip daddr . tcp dport)
  for O(1) policy lookups. Replaces multiple individual accept/drop rules
  with a single hashtable lookup.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | `string` | Map name (e.g., `"fwd_policy"`) |
  | `fields` | `[atom]` | Key fields: `[:ipv4_addr, :ipv4_addr, :inet_service]` |
  | `entries` | `[tuple]` | `[{saddr, daddr, port, verdict}, ...]` |

  ## Examples

      nft_vmap "fwd_policy",
        fields: [:ipv4_addr, :ipv4_addr, :inet_service],
        entries: [
          {{10,0,0,2}, {10,0,1,2}, 4000, :accept},
          {{10,0,1,2}, {10,0,2,2}, 5432, :accept}
        ]

      nft_rule :vmap_lookup, vmap: "fwd_policy"
  """
  defmacro nft_vmap(name, opts) when is_list(opts) do
    fields = Keyword.fetch!(opts, :fields)
    entries = Keyword.get(opts, :entries, [])
    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_concat_vmap(
        var!(ek_nft_table), unquote(name), unquote(fields), unquote(entries))
    end
  end
end
