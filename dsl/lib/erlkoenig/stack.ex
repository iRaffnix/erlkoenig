defmodule Erlkoenig.Stack do
  @moduledoc """
  Unified DSL for the erlkoenig ecosystem.

  Topology and policy in one file, readable by network engineers.

      defmodule MyInfra do
        use Erlkoenig.Stack

        host do
          interface "eth0", zone: :wan
          bridge "br0", subnet: {10, 0, 0, 0, 24}, uplink: "eth0"
          chain "input", hook: :input, policy: :drop do ... end
          chain "forward", hook: :forward, policy: :drop do ... end
        end

        pod "web" do
          container "frontend", binary: "/opt/frontend" do
            chain "inbound", policy: :drop do ... end
          end
        end

        attach "web", to: "br0", replicas: 3
      end

  ## Naming in rules

  Interface names used in `iif:`/`oif:` rules reference:
  - Host interfaces: `"eth0"`, `"lo"`
  - Bridges: `"br0"`
  - Pod containers: `"web.frontend"` (= all replicas of frontend in pod web)

  The compiler resolves pod-qualified names to per-replica IP rules
  at deploy time.
  """

  defmacro __using__(_opts) do
    quote do
      import Erlkoenig.Stack

      Module.register_attribute(__MODULE__, :stack_host, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_pods, accumulate: true)
      Module.register_attribute(__MODULE__, :stack_attachments, accumulate: true)
      Module.register_attribute(__MODULE__, :stack_guard, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_watches, accumulate: true)
      Module.register_attribute(__MODULE__, :stack_nft_tables, accumulate: true)

      Module.put_attribute(__MODULE__, :stack_host, nil)
      Module.put_attribute(__MODULE__, :stack_guard, nil)

      @before_compile Erlkoenig.Stack
    end
  end

  defmacro __before_compile__(env) do
    host = Module.get_attribute(env.module, :stack_host)
    pods = Module.get_attribute(env.module, :stack_pods) |> Enum.reverse()
    attachments = Module.get_attribute(env.module, :stack_attachments) |> Enum.reverse()
    guard_config = Module.get_attribute(env.module, :stack_guard)
    watches = Module.get_attribute(env.module, :stack_watches) |> Enum.reverse()

    # Validate pods
    Enum.each(pods, &Erlkoenig.Pod.Builder.validate!/1)

    pod_names = Enum.map(pods, & &1.name)
    dupes = pod_names -- Enum.uniq(pod_names)
    if dupes != [] do
      raise CompileError,
        description: "duplicate pod names: #{inspect(Enum.uniq(dupes))}"
    end

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

    # Validate attachments reference existing pods and bridges
    bridge_names = if host, do: Enum.map(host.bridges, & &1.name), else: []
    Enum.each(attachments, fn {pod_name, bridge_name, _replicas} ->
      unless pod_name in pod_names do
        raise CompileError,
          description: "attach references unknown pod #{inspect(pod_name)}. " <>
            "Known: #{inspect(pod_names)}"
      end
      unless bridge_name in bridge_names do
        raise CompileError,
          description: "attach references unknown bridge #{inspect(bridge_name)}. " <>
            "Known: #{inspect(bridge_names)}"
      end
    end)

    # Build term — translate host/attach into zones/firewall format
    # that erlkoenig_config understands.
    pods_term = Enum.map(pods, &Erlkoenig.Pod.Builder.to_term/1)

    # Each bridge becomes a zone, each attach becomes a deployment in that zone
    zones_term = if host do
      Enum.map(host.bridges, fn br ->
        deps = attachments
          |> Enum.filter(fn {_pod, bridge, _r} -> bridge == br.name end)
          |> Enum.map(fn {pod, _bridge, replicas} ->
            %{pod: pod, replicas: replicas}
          end)

        zone = %{
          name: br.name,
          subnet: br.subnet,
          gateway: br.gateway,
          netmask: br.netmask,
          bridge: br.name,
          pool: %{start: put_elem(br.subnet, 3, 2),
                  stop: put_elem(br.subnet, 3, 254)}
        }
        zone = if deps != [], do: Map.put(zone, :deployments, deps), else: zone
        zone
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
    table_names = Enum.map(nft_tables, & &1.name)
    table_dupes = table_names -- Enum.uniq(table_names)
    if table_dupes != [] do
      raise CompileError,
        description: "duplicate nft_table names: #{inspect(Enum.uniq(table_dupes))}"
    end

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
  # host — the machine, its interfaces, bridges, firewall
  # ═══════════════════════════════════════════════════════════

  defmacro host(do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :host)

    quote do
      var!(ek_host_builder) = Erlkoenig.Host.Builder.new()
      unquote(block)
      @stack_host var!(ek_host_builder)
    end
  end

  defmacro interface(name, opts \\ []) do
    quote do
      var!(ek_host_builder) = Erlkoenig.Host.Builder.add_interface(
        var!(ek_host_builder), unquote(name), unquote(opts))
    end
  end

  defmacro bridge(name, opts) do
    quote do
      var!(ek_host_builder) = Erlkoenig.Host.Builder.add_bridge(
        var!(ek_host_builder), unquote(name), unquote(opts))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # pod — container group template
  # ═══════════════════════════════════════════════════════════

  defmacro pod(name, opts \\ [], do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :pod)

    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.new(unquote(name), unquote(opts))
      unquote(block)
      @stack_pods var!(ek_pod_builder)
    end
  end

  defmacro container(name, opts) when is_list(opts) do
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_container(
        var!(ek_pod_builder), unquote(to_string(name)), unquote(opts))
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_container(
        var!(ek_pod_builder))
    end
  end

  defmacro container(name, opts, do: block) when is_list(opts) do
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_container(
        var!(ek_pod_builder), unquote(to_string(name)), unquote(opts))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_container(
        var!(ek_pod_builder))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # attach — connect pod to bridge
  # ═══════════════════════════════════════════════════════════

  defmacro attach(pod_name, opts) do
    bridge = Keyword.fetch!(opts, :to)
    replicas = Keyword.get(opts, :replicas, 1)
    quote do
      @stack_attachments {unquote(pod_name), unquote(bridge), unquote(replicas)}
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
  #   oif: "br0"   → oifname: "br0"
  #   ct: :established → ct_state: [:established, :related]
  #   log: "DROP:" → log_prefix: "DROP:"
  # ═══════════════════════════════════════════════════════════

  # ═══════════════════════════════════════════════════════════
  # guard / watch — Erlang runtime
  # ═══════════════════════════════════════════════════════════

  defmacro guard(do: block) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.new()
      unquote(block)
      @stack_guard ErlkoenigNft.Guard.Builder.to_term(var!(ek_guard_builder))
    end
  end

  defmacro detect(type, opts) do
    threshold = Keyword.fetch!(opts, :threshold)
    window = Keyword.fetch!(opts, :window)
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.add_detector(
        var!(ek_guard_builder), unquote(type), unquote(threshold), unquote(window))
    end
  end

  defmacro ban_duration(seconds) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_ban_duration(
        var!(ek_guard_builder), unquote(seconds))
    end
  end

  defmacro whitelist(ip) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.add_whitelist(
        var!(ek_guard_builder), unquote(ip))
    end
  end

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

  defmacro nft_table(family, name, do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :nft_table)

    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.new(unquote(family), unquote(name))
      unquote(block)
      @stack_nft_tables var!(ek_nft_table)
    end
  end

  defmacro base_chain(name, opts, do: block) do
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
  defmacro nft_chain(name, do: block) do
    quote do
      var!(ek_nft_chain) = Erlkoenig.Nft.ChainBuilder.new_regular(unquote(name))
      unquote(block)
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_chain(
        var!(ek_nft_table), var!(ek_nft_chain))
    end
  end

  # rule inside nft_table context — uses nft field names
  defmacro nft_rule(action, opts \\ []) do
    quote do
      var!(ek_nft_chain) = Erlkoenig.Nft.ChainBuilder.add_rule(
        var!(ek_nft_chain), unquote(action), unquote(opts))
    end
  end

  # counter declaration at table level
  defmacro nft_counter(name) do
    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_counter(
        var!(ek_nft_table), unquote(name))
    end
  end

  # set declaration at table level
  defmacro nft_set(name, type, opts \\ []) do
    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_set(
        var!(ek_nft_table), unquote(name), unquote(type), unquote(opts))
    end
  end

  # vmap declaration at table level
  defmacro nft_vmap(name, type, entries) do
    quote do
      var!(ek_nft_table) = Erlkoenig.Nft.TableBuilder.add_vmap(
        var!(ek_nft_table), unquote(name), unquote(type), unquote(entries))
    end
  end
end
