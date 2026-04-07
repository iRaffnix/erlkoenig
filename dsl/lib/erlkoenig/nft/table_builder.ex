#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0

defmodule Erlkoenig.Nft.TableBuilder do
  @moduledoc """
  Accumulates nft table definitions: counters, base_chains, chains.

  A table maps 1:1 to an nf_tables table. One block per table name.
  """

  defstruct family: :inet,
            name: nil,
            counters: [],
            sets: [],
            vmaps: [],
            chains: []

  def new(family, name) do
    %__MODULE__{family: family, name: name}
  end

  def add_counter(%__MODULE__{counters: cs} = t, name) do
    %{t | counters: cs ++ [name]}
  end

  def add_chain(%__MODULE__{chains: cs} = t, chain) do
    %{t | chains: cs ++ [chain]}
  end

  def add_set(%__MODULE__{sets: ss} = t, name, type, opts \\ []) do
    set = case Keyword.get(opts, :elements) do
      nil -> {name, type}
      elems -> {name, type, %{elements: elems}}
    end
    %{t | sets: ss ++ [set]}
  end

  def add_vmap(%__MODULE__{vmaps: vs} = t, name, type, entries) do
    vmap = %{name: name, type: type, entries: entries}
    %{t | vmaps: vs ++ [vmap]}
  end

  def validate!(%__MODULE__{} = t) do
    if t.chains == [] do
      raise CompileError,
        description: "nft_table #{inspect(t.name)}: must have at least one chain"
    end

    # Check chain name uniqueness
    Erlkoenig.Validation.check_uniqueness(t.chains, :name, "chain names in nft_table #{inspect(t.name)}")

    # Check counter references exist
    declared_counters = MapSet.new(t.counters)
    all_rules = Enum.flat_map(t.chains, & &1.rules)
    Enum.each(all_rules, fn {_action, opts} ->
      case Map.get(opts, :counter) do
        nil -> :ok
        name ->
          unless MapSet.member?(declared_counters, name) do
            raise CompileError,
              description: "nft_table #{inspect(t.name)}: counter #{inspect(name)} referenced but not declared"
          end
      end
    end)

    :ok
  end

  def to_term(%__MODULE__{} = t) do
    base = %{
      family: t.family,
      name: t.name,
      counters: t.counters,
      chains: Enum.map(t.chains, &chain_to_term/1)
    }
    base = if t.sets != [], do: Map.put(base, :sets, t.sets), else: base
    base = if t.vmaps != [], do: Map.put(base, :vmaps, t.vmaps), else: base
    base
  end

  defp chain_to_term(%{type: :base} = c) do
    base = %{
      name: c.name,
      hook: c.hook,
      type: c.chain_type,
      priority: c.priority,
      policy: c.policy,
      rules: c.rules
    }
    base
  end

  defp chain_to_term(c) do
    %{
      name: c.name,
      rules: c.rules
    }
  end
end
