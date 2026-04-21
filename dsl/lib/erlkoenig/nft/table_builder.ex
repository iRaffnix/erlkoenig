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
            maps: [],
            vmaps: [],
            flowtables: [],
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
    # Collect every meaningful option into the opts map that the
    # runtime consumes. Today the Erlang nft_firewall honors
    # `elements`, `flags`, and `timeout`; anything else passed here
    # travels along for future hooks but is ignored by the current
    # kernel-loader path.
    meta =
      %{}
      |> put_if_list(opts, :flags)
      |> put_if_list(opts, :elements)
      |> put_if_integer(opts, :timeout)

    set =
      if map_size(meta) == 0 do
        {name, type}
      else
        {name, type, meta}
      end

    %{t | sets: ss ++ [set]}
  end

  defp put_if_list(map, opts, key) do
    case Keyword.get(opts, key) do
      nil -> map
      list when is_list(list) -> Map.put(map, key, list)
      _ -> map
    end
  end

  defp put_if_integer(map, opts, key) do
    case Keyword.get(opts, key) do
      nil -> map
      n when is_integer(n) -> Map.put(map, key, n)
      _ -> map
    end
  end

  @doc """
  Add a CIDR-style ipv4 set: flags [:interval] + static elements.

  Rejects nonsense at compile time so the runtime never sees a
  set that would load zero elements and silently break an allow-
  list. See `Erlkoenig.Stack.nft_cidr_set/2` for DSL docs.
  """
  def add_cidr_set(%__MODULE__{} = t, name, cidrs) do
    validate_cidr_list!(name, cidrs)
    add_set(t, name, :ipv4_addr,
      flags: [:interval],
      elements: cidrs)
  end

  defp validate_cidr_list!(name, []) do
    raise CompileError,
      description:
        "nft_cidr_set #{inspect(name)}: list must not be empty — " <>
          "an interval set with zero elements matches nothing"
  end

  defp validate_cidr_list!(name, cidrs) when is_list(cidrs) do
    Enum.each(cidrs, fn
      cidr when is_binary(cidr) ->
        unless cidr =~ ~r/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/ do
          raise CompileError,
            description:
              "nft_cidr_set #{inspect(name)}: " <>
                "#{inspect(cidr)} is not a valid IPv4 CIDR or address"
        end

      bad ->
        raise CompileError,
          description:
            "nft_cidr_set #{inspect(name)}: " <>
              "each entry must be a string, got #{inspect(bad)}"
    end)
  end

  defp validate_cidr_list!(name, _not_list) do
    raise CompileError,
      description:
        "nft_cidr_set #{inspect(name)}: second argument must be a list of strings"
  end

  def add_map(%__MODULE__{maps: ms} = t, name, key_type, data_type, entries) do
    map = %{name: name, key_type: key_type, data_type: data_type, entries: entries}
    %{t | maps: ms ++ [map]}
  end

  # Accept the three supported shapes for map entries.  Called from
  # the `nft_map` macro after quoting, so it operates on the raw
  # values the operator passed.
  def normalize_map_entries({:replica_ips, _pod, _ct} = ref), do: ref
  def normalize_map_entries([]), do: []
  def normalize_map_entries(list) when is_list(list) do
    cond do
      Keyword.keyword?(list) -> Keyword.get(list, :entries, [])
      Enum.all?(list, &match?({_, _}, &1)) -> list
      true ->
        raise CompileError,
          description:
            "nft_map entries must be a keyword list `[entries: [...]]`, " <>
              "a positional list of `{key, value}` tuples, or " <>
              "`{:replica_ips, pod, ct}`; got #{inspect(list)}"
    end
  end
  def normalize_map_entries(other) do
    raise CompileError,
      description:
        "nft_map entries: unexpected shape #{inspect(other)}"
  end

  def add_vmap(%__MODULE__{vmaps: vs} = t, name, type, entries) do
    vmap = %{name: name, type: type, entries: entries}
    %{t | vmaps: vs ++ [vmap]}
  end

  def add_concat_vmap(%__MODULE__{vmaps: vs} = t, name, fields, entries) do
    vmap = %{name: name, fields: fields, entries: entries, concat: true}
    %{t | vmaps: vs ++ [vmap]}
  end

  def add_flowtable(%__MODULE__{flowtables: fts} = t, name, opts) do
    devices = Keyword.get(opts, :devices, [])
    priority = Keyword.get(opts, :priority, 0)

    if devices == [] do
      raise CompileError,
        description: "nft_flowtable #{inspect(name)}: devices: must list at least one interface"
    end

    ft = %{
      name: name,
      hook: :ingress,
      priority: priority,
      devices: devices
    }
    %{t | flowtables: fts ++ [ft]}
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

    # Check vmap jump targets exist as declared chains in the same table.
    # Without this check the batch apply fails lazily in the kernel
    # with `{-2, enoent}` because the vmap element references a chain
    # that was never created — and the entire atomic batch rolls back,
    # leaving the operator with an empty table and no error pointing
    # at the actual cause (see Bug #2, tutorial 03).
    declared_chains = MapSet.new(Enum.map(t.chains, & &1.name))
    Enum.each(t.vmaps, fn vmap ->
      Enum.each(vmap.entries, fn
        {_key, {:jump, chain}} ->
          unless MapSet.member?(declared_chains, chain) do
            raise CompileError,
              description:
                "nft_table #{inspect(t.name)}: nft_vmap #{inspect(vmap.name)} " <>
                  "has entry jumping to chain #{inspect(chain)} which is not " <>
                  "declared in the same table. Declared chains: " <>
                  inspect(MapSet.to_list(declared_chains)) <>
                  ". The kernel rejects vmap elements that reference " <>
                  "non-existent chains with ENOENT, rolling back the " <>
                  "entire atomic batch."
          end

        {_key, {:goto, chain}} ->
          unless MapSet.member?(declared_chains, chain) do
            raise CompileError,
              description:
                "nft_table #{inspect(t.name)}: nft_vmap #{inspect(vmap.name)} " <>
                  "has entry goto chain #{inspect(chain)} which is not declared"
          end

        _ ->
          :ok
      end)
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
    base = if t.maps != [], do: Map.put(base, :maps, t.maps), else: base
    base = if t.vmaps != [], do: Map.put(base, :vmaps, t.vmaps), else: base
    base = if t.flowtables != [], do: Map.put(base, :flowtables, t.flowtables), else: base
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
