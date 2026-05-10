defmodule Erlkoenig.Ontology.Compiler do
  @moduledoc """
  Emits ontology worlds from validated Erlkoenig DSL builder state.
  """

  alias Erlkoenig.Ontology.{Fact, Schema, World}

  @type stack_data :: %{
          module: module(),
          host: term(),
          pods: list(),
          nft_tables: list(),
          guard: map() | nil,
          watches: list()
        }

  @spec from_stack(stack_data()) :: World.t()
  def from_stack(%{module: module} = data) do
    schema = Schema.default()
    stack_ref = {:stack, inspect(module)}

    facts =
      []
      |> add_stack(stack_ref, module, Map.get(data, :origin))
      |> add_host(stack_ref, Map.get(data, :host))
      |> add_pods(stack_ref, Map.get(data, :pods, []))
      |> add_nft_tables(stack_ref, Map.get(data, :nft_tables, []))
      |> add_guard(stack_ref, Map.get(data, :guard))
      |> add_watches(stack_ref, Map.get(data, :watches, []))
      |> Enum.reverse()

    World.new(facts, schema)
  end

  defp add_stack(facts, stack_ref, module, origin) do
    [fact(:stack, elem(stack_ref, 1), %{module: inspect(module)}, [], origin) | facts]
  end

  defp add_host(facts, _stack_ref, nil), do: facts

  defp add_host(facts, stack_ref, host) do
    host_ref = {:host, "host"}

    facts = [fact(:host, "host", %{}, [{:has_host, stack_ref}]) | facts]

    facts =
      Enum.reduce(host.interfaces, facts, fn iface, acc ->
        id = namespace("host", iface.name)

        [
          fact(:interface, id, %{name: iface.name, zone: iface.zone}, [
            {:has_interface, host_ref}
          ])
          | acc
        ]
      end)

    Enum.reduce(host.ipvlans, facts, fn ipvlan, acc ->
      id = to_string(ipvlan.name)

      [
        fact(
          :zone,
          id,
          %{
            name: ipvlan.name,
            parent: ipvlan.parent,
            parent_type: ipvlan.parent_type,
            subnet: ipvlan.subnet,
            netmask: ipvlan.netmask,
            ipvlan_mode: ipvlan.ipvlan_mode,
            gateway: ipvlan.gateway
          },
          [{:has_zone, host_ref}]
        )
        | acc
      ]
    end)
  end

  defp add_pods(facts, stack_ref, pods) do
    Enum.reduce(pods, facts, fn pod, acc ->
      pod_ref = {:pod, pod.name}

      acc =
        [
          fact(:pod, pod.name, %{name: pod.name, strategy: pod.strategy}, [
            {:has_pod, stack_ref}
          ])
          | acc
        ]

      Enum.reduce(pod.containers, acc, fn container, acc ->
        add_container(acc, pod_ref, pod.name, container)
      end)
    end)
  end

  defp add_container(facts, pod_ref, pod_name, container) do
    id = namespace(pod_name, container.name)
    container_ref = {:container, id}

    properties =
      container
      |> Map.take([
        :name,
        :binary,
        :image,
        :zone,
        :replicas,
        :restart,
        :ports,
        :limits,
        :seccomp,
        :uid,
        :gid,
        :args,
        :caps,
        :env
      ])

    facts =
      [
        fact(:container, id, properties, [
          {:has_container, pod_ref},
          {:runs_in_zone, {:zone, container.zone}}
        ])
        | facts
      ]

    facts =
      Enum.reduce(container.requires, facts, fn capability, acc ->
        cap_id = namespace(id, Atom.to_string(capability))

        [
          fact(:capability, cap_id, %{name: capability}, [
            {:requires_capability, container_ref}
          ])
          | acc
        ]
      end)

    facts =
      Enum.reduce(container.volumes, facts, fn volume, acc ->
        volume_id = namespace(id, Map.get(volume, :container, "volume"))

        [
          fact(:volume, volume_id, volume, [{:mounts_volume, container_ref}])
          | acc
        ]
      end)

    facts =
      Enum.reduce(container.publish, facts, fn publish, acc ->
        publish_id = namespace(id, "publish")

        [
          fact(:publish, publish_id, publish, [{:publishes_metric, container_ref}])
          | acc
        ]
      end)

    facts =
      if container.stream do
        stream_id = namespace(id, "stream")
        [fact(:stream, stream_id, container.stream, [{:streams_channel, container_ref}]) | facts]
      else
        facts
      end

    add_container_nft(facts, container_ref, id, Map.get(container, :nft))
  end

  defp add_container_nft(facts, _container_ref, _namespace, nil), do: facts

  defp add_container_nft(facts, container_ref, namespace, nft) do
    Enum.reduce(nft.chains, facts, fn chain, acc ->
      chain_id = namespace(namespace, chain.name)
      chain_ref = {:nft_chain, chain_id}

      acc =
        [
          fact(:nft_chain, chain_id, chain_properties(chain), [
            {:has_chain, container_ref}
          ])
          | acc
        ]

      add_rules(acc, chain_ref, chain_id, chain.rules)
    end)
  end

  defp add_nft_tables(facts, stack_ref, tables) do
    Enum.reduce(tables, facts, fn table, acc ->
      table_id = table.name
      table_ref = {:nft_table, table_id}

      acc =
        [
          fact(
            :nft_table,
            table_id,
            %{family: table.family, name: table.name, owner: table.owner},
            [{:has_nft_table, stack_ref}]
          )
          | acc
        ]

      acc = add_named(acc, :nft_counter, :uses_counter, table_ref, table_id, table.counters)
      acc = add_sets(acc, table_ref, table_id, table.sets)
      acc = add_maps(acc, table_ref, table_id, table.maps, :nft_map, :uses_map)
      acc = add_maps(acc, table_ref, table_id, table.vmaps, :nft_vmap, :uses_vmap)
      acc = add_maps(acc, table_ref, table_id, table.flowtables, :nft_flowtable, :uses_flowtable)

      acc =
        Enum.reduce(table.nflog_groups, acc, fn group, group_acc ->
          id = namespace(table_id, group.group)

          [
            fact(:nflog_group, id, group, [{:logs_to_nflog_group, table_ref}])
            | group_acc
          ]
        end)

      Enum.reduce(table.chains, acc, fn chain, chain_acc ->
        chain_id = namespace(table_id, chain.name)
        chain_ref = {:nft_chain, chain_id}

        chain_acc =
          [
            fact(:nft_chain, chain_id, chain_properties(chain), [
              {:has_chain, table_ref}
            ])
            | chain_acc
          ]

        add_rules(chain_acc, chain_ref, chain_id, chain.rules)
      end)
    end)
  end

  defp add_named(facts, type, relation, parent_ref, namespace, names) do
    Enum.reduce(names, facts, fn name, acc ->
      id = namespace(namespace, name)
      [fact(type, id, %{name: name}, [{relation, parent_ref}]) | acc]
    end)
  end

  defp add_sets(facts, parent_ref, namespace, sets) do
    Enum.reduce(sets, facts, fn set, acc ->
      {name, type, properties} =
        case set do
          {name, type} -> {name, type, %{}}
          {name, type, meta} -> {name, type, meta}
        end

      id = namespace(namespace, name)

      [
        fact(:nft_set, id, Map.merge(%{name: name, set_type: type}, properties), [
          {:uses_set, parent_ref}
        ])
        | acc
      ]
    end)
  end

  defp add_maps(facts, parent_ref, namespace, maps, type, relation) do
    Enum.reduce(maps, facts, fn map, acc ->
      id = namespace(namespace, map.name)
      [fact(type, id, map, [{relation, parent_ref}]) | acc]
    end)
  end

  defp add_rules(facts, chain_ref, namespace, rules) do
    rules
    |> Enum.with_index(1)
    |> Enum.reduce(facts, fn {{action, opts}, index}, acc ->
      id = namespace(namespace, "rule_#{index}")

      links =
        [{:has_rule, chain_ref}, {:performs_action, chain_ref}] ++
          rule_links(opts)

      [fact(:nft_rule, id, %{action: action, opts: opts}, links) | acc]
    end)
  end

  defp rule_links(opts) do
    []
    |> maybe_rule_link(opts, :counter, :uses_counter, :nft_counter)
    |> maybe_rule_link(opts, :set, :uses_set, :nft_set)
    |> maybe_rule_link(opts, :vmap, :uses_vmap, :nft_vmap)
    |> maybe_rule_link(opts, :map, :uses_map, :nft_map)
    |> maybe_rule_link(opts, :flowtable, :uses_flowtable, :nft_flowtable)
    |> maybe_rule_link(opts, :nflog_group, :logs_to_nflog_group, :nflog_group)
  end

  defp maybe_rule_link(links, opts, key, relation, type) do
    case Map.get(opts, key) do
      nil -> links
      value -> [{relation, {:external, type, value}} | links]
    end
  end

  defp add_guard(facts, _stack_ref, nil), do: facts

  defp add_guard(facts, stack_ref, guard) do
    [fact(:guard, "guard", guard, [{:has_guard, stack_ref}]) | facts]
  end

  defp add_watches(facts, stack_ref, watches) do
    Enum.reduce(watches, facts, fn watch, acc ->
      id = Map.fetch!(watch, :name)
      [fact(:watch, id, watch, [{:has_watch, stack_ref}]) | acc]
    end)
  end

  defp chain_properties(chain) do
    if is_struct(chain) do
      chain
      |> Map.from_struct()
      |> Map.delete(:rules)
    else
      Map.delete(chain, :rules)
    end
  end

  defp fact(type, id, properties, links), do: fact(type, id, properties, links, nil)

  defp fact(type, id, properties, links, origin) do
    %Fact{
      ref: {type, id},
      type: type,
      properties: properties,
      metadata: nil,
      links: links,
      origin: origin
    }
  end

  defp namespace(parent, child), do: "#{parent}.#{child}"
end
