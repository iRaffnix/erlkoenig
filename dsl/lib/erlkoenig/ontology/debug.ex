#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

defmodule Erlkoenig.Ontology.Debug do
  @moduledoc """
  Render an operator-oriented debug report from an ontology world.

  This is deliberately not a graph renderer. It turns the same facts
  used by Mermaid/JSON into a compact ownership view: which objects a
  container explains, and which per-container nft rules should vanish
  when that container is gone.
  """

  alias Erlkoenig.Ontology.{Fact, World}

  @attached_types [
    :capability,
    :volume,
    :publish,
    :stream,
    :nft_chain
  ]

  @doc """
  Render the container ownership/debug view as text.
  """
  @spec render(World.t()) :: iodata()
  def render(%World{facts: facts}) do
    containers = Enum.filter(facts, &(&1.type == :container))

    [
      "Ontology debug report\n",
      "containers: ",
      Integer.to_string(length(containers)),
      "\n",
      scope_summary(facts),
      "\n\n",
      Enum.map(containers, &container_section(&1, facts)),
      global_nft_section(facts)
    ]
  end

  defp container_section(%Fact{} = container, facts) do
    direct = direct_children(container.ref, facts)
    chains = Enum.filter(direct, &(&1.type == :nft_chain))

    [
      "container ",
      ref_id(container.ref),
      "\n",
      "  name: ",
      prop(container, :name),
      "\n",
      "  pod: ",
      linked_id(container, :has_container),
      "\n",
      "  zone: ",
      linked_id(container, :runs_in_zone),
      "\n",
      "  explains:\n",
      attached_lines(direct),
      "  cleanup candidates:\n",
      cleanup_lines(chains, facts),
      "\n"
    ]
  end

  defp scope_summary(facts) do
    container_chains = scoped_facts(facts, :nft_chain, :container)
    container_rules = rules_for_chains(container_chains, facts)
    global_tables = facts |> Enum.filter(&(&1.type == :nft_table))
    global_children = Enum.flat_map(global_tables, &table_children(&1.ref, facts))
    global_chains = Enum.filter(global_children, &(&1.type == :nft_chain))
    global_rules = rules_for_chains(global_chains, facts)
    global_counters = Enum.filter(global_children, &(&1.type == :nft_counter))
    global_nflog = Enum.filter(global_children, &(&1.type == :nflog_group))

    [
      "scope summary:\n",
      "  container-scope nft: ",
      count("chains", container_chains),
      ", ",
      count("rules", container_rules),
      "\n",
      "  stack-global nft: ",
      count("tables", global_tables),
      ", ",
      count("chains", global_chains),
      ", ",
      count("rules", global_rules),
      ", ",
      count("counters", global_counters),
      ", ",
      count("nflog_groups", global_nflog)
    ]
  end

  defp scoped_facts(facts, fact_type, target_type) do
    Enum.filter(facts, fn fact ->
      fact.type == fact_type and
        Enum.any?(fact.links, fn {_relation, ref} -> ref_type(ref) == target_type end)
    end)
  end

  defp rules_for_chains(chains, facts) do
    chains
    |> Enum.flat_map(&rules_for_chain(&1.ref, facts))
    |> Enum.uniq_by(& &1.ref)
  end

  defp count(label, values), do: Integer.to_string(length(values)) <> " " <> label

  defp direct_children(parent_ref, facts) do
    facts
    |> Enum.filter(fn fact ->
      fact.type in @attached_types and Enum.any?(fact.links, &link_targets?(&1, parent_ref))
    end)
    |> Enum.sort_by(&sort_key/1)
  end

  defp attached_lines([]), do: ["    (none)\n"]

  defp attached_lines(facts) do
    Enum.map(facts, fn fact ->
      ["    ", Atom.to_string(fact.type), " ", ref_id(fact.ref), summary(fact), "\n"]
    end)
  end

  defp cleanup_lines([], _facts), do: ["    (no per-container nft chains)\n"]

  defp cleanup_lines(chains, facts) do
    Enum.flat_map(chains, fn chain ->
      rules = rules_for_chain(chain.ref, facts)

      [
        ["    nft_chain ", ref_id(chain.ref), "\n"],
        Enum.map(rules, fn rule ->
          ["      nft_rule ", ref_id(rule.ref), rule_summary(rule), "\n"]
        end)
      ]
    end)
  end

  defp global_nft_section(facts) do
    tables = facts |> Enum.filter(&(&1.type == :nft_table)) |> Enum.sort_by(&sort_key/1)

    [
      "stack-global nft objects\n",
      global_table_lines(tables, facts)
    ]
  end

  defp global_table_lines([], _facts), do: ["  (none)\n"]

  defp global_table_lines(tables, facts) do
    Enum.map(tables, fn table ->
      children = table_children(table.ref, facts)
      chains = Enum.filter(children, &(&1.type == :nft_chain))
      counters = Enum.filter(children, &(&1.type == :nft_counter))
      nflog_groups = Enum.filter(children, &(&1.type == :nflog_group))

      [
        "  nft_table ",
        ref_id(table.ref),
        " owner=",
        prop(table, :owner),
        " family=",
        prop(table, :family),
        "\n",
        "    persistent while stack/host policy is active\n",
        "    counters:\n",
        object_lines(counters),
        "    nflog groups:\n",
        object_lines(nflog_groups),
        "    chains:\n",
        global_chain_lines(chains, facts)
      ]
    end)
  end

  defp table_children(table_ref, facts) do
    facts
    |> Enum.filter(fn fact ->
      fact.type in [
        :nft_chain,
        :nft_counter,
        :nft_set,
        :nft_map,
        :nft_vmap,
        :nft_flowtable,
        :nflog_group
      ] and
        Enum.any?(fact.links, &link_targets?(&1, table_ref))
    end)
    |> Enum.sort_by(&sort_key/1)
  end

  defp object_lines([]), do: ["      (none)\n"]

  defp object_lines(facts) do
    Enum.map(facts, fn fact ->
      ["      ", Atom.to_string(fact.type), " ", ref_id(fact.ref), summary(fact), "\n"]
    end)
  end

  defp global_chain_lines([], _facts), do: ["      (none)\n"]

  defp global_chain_lines(chains, facts) do
    Enum.map(chains, fn chain ->
      [
        "      nft_chain ",
        ref_id(chain.ref),
        summary(chain),
        " owner=",
        prop(chain, :owner),
        "\n",
        Enum.map(rules_for_chain(chain.ref, facts), fn rule ->
          ["        nft_rule ", ref_id(rule.ref), rule_summary(rule), "\n"]
        end)
      ]
    end)
  end

  defp rules_for_chain(chain_ref, facts) do
    facts
    |> Enum.filter(fn fact ->
      fact.type == :nft_rule and Enum.any?(fact.links, &link_targets?(&1, chain_ref))
    end)
    |> Enum.sort_by(&sort_key/1)
  end

  defp linked_id(%Fact{links: links}, relation) do
    links
    |> Enum.find_value("(unknown)", fn
      {^relation, ref} -> ref_id(ref)
      _ -> nil
    end)
  end

  defp link_targets?({_relation, target_ref}, parent_ref), do: target_ref == parent_ref

  defp summary(%Fact{type: :capability} = fact), do: " name=" <> prop(fact, :name)
  defp summary(%Fact{type: :publish} = fact), do: " metrics=" <> prop(fact, :metrics)
  defp summary(%Fact{type: :stream} = fact), do: " channels=" <> prop(fact, :channels)
  defp summary(%Fact{type: :volume} = fact), do: " mount=" <> prop(fact, :container)
  defp summary(%Fact{type: :nft_chain} = fact), do: " hook=" <> prop(fact, :hook)
  defp summary(%Fact{type: :nft_counter} = fact), do: " name=" <> prop(fact, :name)
  defp summary(%Fact{type: :nflog_group} = fact), do: " group=" <> prop(fact, :group)
  defp summary(_fact), do: ""

  defp rule_summary(%Fact{properties: props}) do
    action = Map.get(props, :action) || Map.get(props, "action") || "?"
    opts = Map.get(props, :opts) || Map.get(props, "opts") || %{}
    " action=" <> value(action) <> interesting_opts(opts)
  end

  defp interesting_opts(opts) when is_map(opts) do
    [:counter, :set, :map, :vmap, :flowtable, :nflog_group]
    |> Enum.flat_map(fn key ->
      case Map.get(opts, key) || Map.get(opts, Atom.to_string(key)) do
        nil -> []
        value -> [" ", Atom.to_string(key), "=", value(value)]
      end
    end)
    |> IO.iodata_to_binary()
  end

  defp interesting_opts(_opts), do: ""

  defp prop(%Fact{properties: props}, key) do
    props
    |> Map.get(key, Map.get(props, Atom.to_string(key), "(none)"))
    |> value()
  end

  defp ref_id({:external, type, id}), do: "external:" <> Atom.to_string(type) <> ":" <> value(id)
  defp ref_id({_type, id}), do: value(id)

  defp ref_type({:external, type, _id}), do: type
  defp ref_type({type, _id}), do: type

  defp sort_key(%Fact{ref: {type, id}}), do: {Atom.to_string(type), value(id)}

  defp value(v) when is_binary(v), do: v
  defp value(v) when is_atom(v), do: Atom.to_string(v)
  defp value(v), do: inspect(v)
end
