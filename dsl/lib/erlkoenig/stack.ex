defmodule Erlkoenig.Stack do
  @moduledoc """
  Unified DSL for the erlkoenig ecosystem.

  Topology and policy in one file, readable by network engineers. One
  `pod` is the **logical bracket** around all containers that belong
  together; each container declares its own `zone:` inline. Multiple
  instances are written with explicit `for_each` loops, so generated
  names and per-instance options stay visible in the stack file.
  There is no separate `attach` step.

      defmodule MyInfra do
        use Erlkoenig.Stack

        host do
          ipvlan "dmz", parent: {:device, "eth0"}, subnet: {10, 0, 0, 0, 24}

          nft_host do
            base_chain "input", hook: :input, type: :filter,
              priority: :filter, policy: :drop do
              nft_rule :accept, ct_state: [:established, :related]
              nft_rule :drop
            end
          end
        end

        pod "web", strategy: :one_for_one do
          for_each i <- 0..2 do
            container "frontend-\#{i}",
              binary: "/opt/frontend",
              zone: "dmz",
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
      end

  ## Required options (nothing implicit)

  - `pod`: `strategy:`
  - `container`: `binary:`, `zone:`, `restart:`

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
      import Erlkoenig.Stack.HostMacros
      import Erlkoenig.Stack.ContainerMacros
      import Erlkoenig.Stack.NftMacros
      import Erlkoenig.Stack.GuardMacros
      import Erlkoenig.Stack.WatchMacros
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
    all_container_names =
      Enum.flat_map(pods, fn pod ->
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
            description:
              "container #{inspect(pod.name)}/#{inspect(ct.name)}: " <>
                "zone #{inspect(ct.zone)} is not declared by any `ipvlan`. " <>
                "Known zones: #{inspect(zone_names)}"
        end
      end)
    end)

    # Build term
    pods_term = Enum.map(pods, &Erlkoenig.Pod.Builder.to_term/1)

    # Each ipvlan becomes a zone. Zones no longer carry `deployments` —
    # each container inside a pod carries its own `zone:`.
    zones_term =
      if host do
        Enum.map(host.ipvlans, fn ipv ->
          zone = %{
            name: ipv.name,
            subnet: ipv.subnet,
            netmask: ipv.netmask,
            network: %{
              mode: :ipvlan,
              parent: ipv.parent,
              parent_type: ipv.parent_type,
              ipvlan_mode: ipv.ipvlan_mode
            },
            pool: %{start: put_elem(ipv.subnet, 3, 2), stop: put_elem(ipv.subnet, 3, 254)}
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

    ontology_data = %{
      module: env.module,
      origin: Erlkoenig.Ontology.Origin.from_caller(env, :stack),
      host: host,
      pods: pods,
      nft_tables: nft_tables,
      guard: guard_config,
      watches: watches
    }

    quote do
      def config, do: unquote(Macro.escape(term))

      def ontology do
        Erlkoenig.Ontology.Compiler.from_stack(unquote(Macro.escape(ontology_data)))
      end

      def write!(path) do
        formatted = :io_lib.format(~c"~tp.~n", [config()])
        File.write!(path, formatted)
      end
    end
  end
end
