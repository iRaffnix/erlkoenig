#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0

defmodule Erlkoenig.Nft.TableBuilder do
  @moduledoc """
  Accumulates nft table definitions: counters, base_chains, chains.

  A table maps 1:1 to an nf_tables table. One block per table name.

  The `:owner` field is the single authoritative writer of ownership
  per Spec SPEC-NFT-OWNERSHIP-SPLIT §7. It is set by the enclosing
  block macro (`nft_host` / `nft_zone` / `nft_ct` /
  `nft_in_container`), and the validator
  enforces that every chain in the table carries the same owner.
  Chain / set / counter / map / vmap / flowtable constructors do
  not accept an owner argument — owner is copied during the
  finalization pass.
  """

  @valid_owners [:host, :zone, :ct, :in_container]

  defstruct family: :inet,
            name: nil,
            owner: nil,
            counters: [],
            sets: [],
            maps: [],
            vmaps: [],
            flowtables: [],
            nflog_groups: [],
            chains: []

  @type owner :: :host | :zone | :ct | :in_container
  @type t :: %__MODULE__{
          family: atom(),
          name: String.t() | atom() | nil,
          owner: owner() | nil,
          counters: list(),
          sets: list(),
          maps: list(),
          vmaps: list(),
          flowtables: list(),
          nflog_groups: list(),
          chains: list()
        }

  @spec new(atom(), String.t() | atom(), keyword()) :: t()
  def new(family, name, opts \\ []) do
    owner =
      Keyword.get_lazy(opts, :owner, fn ->
        raise CompileError,
          description:
            "nft table #{inspect(name)} must declare an explicit owner " <>
              "(one of #{inspect(@valid_owners)}). Use nft_host / nft_zone / " <>
              "nft_ct / nft_in_container instead of constructing raw tables."
      end)

    unless owner in @valid_owners do
      raise CompileError,
        description:
          "nft table #{inspect(name)}: invalid owner #{inspect(owner)} — " <>
            "must be one of #{inspect(@valid_owners)}"
    end

    %__MODULE__{family: family, name: name, owner: owner}
  end

  @doc "List of valid owner atoms (Spec §7)."
  def valid_owners, do: @valid_owners

  def add_counter(%__MODULE__{counters: cs} = t, name) do
    %{t | counters: cs ++ [name]}
  end

  def add_chain(%__MODULE__{chains: cs, owner: owner} = t, chain) do
    # Finalization pass: stamp the table's owner onto the chain.
    # Chains are constructed without an owner argument; this is
    # the only writer (per Spec §7 owner-model contract). If a
    # caller hands in a chain whose owner is already set and
    # differs from the table's owner, we surface that loud — that
    # is the "second source of truth" failure mode the contract
    # is meant to make impossible.
    case Map.get(chain, :owner) do
      nil ->
        %{t | chains: cs ++ [%{chain | owner: owner}]}

      ^owner ->
        %{t | chains: cs ++ [chain]}

      other ->
        raise CompileError,
          description:
            "nft_table #{inspect(t.name)} (owner #{inspect(owner)}): chain " <>
              "#{inspect(chain.name)} arrived with owner #{inspect(other)}. " <>
              "Chains must not be constructed with an explicit owner — " <>
              "owner is copied from the enclosing block (Spec §7)."
    end
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
      elements: cidrs
    )
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
      description: "nft_cidr_set #{inspect(name)}: second argument must be a list of strings"
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
      Keyword.keyword?(list) ->
        Keyword.get(list, :entries, [])

      Enum.all?(list, &match?({_, _}, &1)) ->
        list

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
      description: "nft_map entries: unexpected shape #{inspect(other)}"
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

  def add_nflog_group(%__MODULE__{nflog_groups: groups} = t, group, opts \\ []) do
    unless is_integer(group) and group >= 0 do
      raise CompileError,
        description: "nft_nflog_group #{inspect(group)}: group must be a non-negative integer"
    end

    meta =
      %{
        group: group,
        name: Keyword.get(opts, :name, "group_#{group}")
      }
      |> put_if_binary_or_string(opts, :description)

    %{t | nflog_groups: groups ++ [meta]}
  end

  defp put_if_binary_or_string(map, opts, key) do
    case Keyword.get(opts, key) do
      nil -> map
      value when is_binary(value) or is_list(value) -> Map.put(map, key, value)
      _ -> map
    end
  end

  @spec validate!(t()) :: t()
  def validate!(%__MODULE__{} = t) do
    if t.chains == [] do
      raise CompileError,
        description: "nft_table #{inspect(t.name)}: must have at least one chain"
    end

    # Owner-model invariant (Spec §7): every chain's denormalized
    # owner tag must match the table's authoritative owner. The
    # only writer is `add_chain/2`, so a divergence at this point
    # would be a downstream bug — but checking here keeps the
    # invariant locally enforced and audit-visible at compile time.
    Enum.each(t.chains, fn chain ->
      case Map.get(chain, :owner) do
        nil ->
          raise CompileError,
            description:
              "nft_table #{inspect(t.name)} (owner #{inspect(t.owner)}): chain " <>
                "#{inspect(chain.name)} has no owner tag. " <>
                "This is a TableBuilder invariant failure (Spec §7)."

        owner when owner == t.owner ->
          :ok

        other ->
          raise CompileError,
            description:
              "nft_table #{inspect(t.name)} (owner #{inspect(t.owner)}): chain " <>
                "#{inspect(chain.name)} carries divergent owner #{inspect(other)}. " <>
                "Mixed ownership inside one table is a hard violation of " <>
                "Spec §7 — if you need this, use a different block."
      end
    end)

    # Check chain name uniqueness
    Erlkoenig.Validation.check_uniqueness(
      t.chains,
      :name,
      "chain names in nft_table #{inspect(t.name)}"
    )

    # Check name uniqueness across every named object in the table.
    # The kernel rejects a batch containing two NEWSET / NEWMAP / NEWFLOWTABLE
    # with the same name (EEXIST) and rolls the ENTIRE atomic transaction
    # back — the operator then sees "batch failed" without a pointer at
    # the actual collision. Catching here moves the diagnostic to compile
    # time and names the offender.
    ensure_unique_names!(t.counters, "counter names in nft_table #{inspect(t.name)}")
    ensure_unique_names!(set_names(t.sets), "set names in nft_table #{inspect(t.name)}")

    ensure_unique_names!(
      Enum.map(t.maps, & &1.name),
      "map names in nft_table #{inspect(t.name)}"
    )

    ensure_unique_names!(
      Enum.map(t.vmaps, & &1.name),
      "vmap names in nft_table #{inspect(t.name)}"
    )

    ensure_unique_names!(
      Enum.map(t.flowtables, & &1.name),
      "flowtable names in nft_table #{inspect(t.name)}"
    )

    ensure_unique_names!(
      Enum.map(t.nflog_groups, & &1.group),
      "nflog groups in nft_table #{inspect(t.name)}"
    )

    # Check counter references exist
    declared_counters = MapSet.new(t.counters)
    declared_nflog_groups = MapSet.new(Enum.map(t.nflog_groups, & &1.group))
    all_rules = Enum.flat_map(t.chains, & &1.rules)

    Enum.each(all_rules, fn {_action, opts} ->
      case Map.get(opts, :counter) do
        nil ->
          :ok

        name ->
          unless MapSet.member?(declared_counters, name) do
            raise CompileError,
              description:
                "nft_table #{inspect(t.name)}: counter #{inspect(name)} referenced but not declared"
          end
      end

      case {Map.get(opts, :log), Map.get(opts, :log_prefix), Map.get(opts, :nflog_group)} do
        {nil, nil, nil} ->
          :ok

        {nil, nil, group} ->
          ensure_declared_nflog_group!(t, declared_nflog_groups, group)

        {_log, _prefix, nil} ->
          raise CompileError,
            description:
              "nft_table #{inspect(t.name)}: logged nft_rule must declare " <>
                "nflog_group: N and the table must declare `nft_nflog_group N`"

        {_log, _prefix, group} ->
          ensure_declared_nflog_group!(t, declared_nflog_groups, group)
      end
    end)

    # Check vmap jump targets exist as declared chains in the same table.
    # Without this check the batch apply fails lazily in the kernel
    # with `{-2, enoent}` because the vmap element references a chain
    # that was never created — and the entire atomic batch rolls back,
    # leaving the operator with an empty table and no error pointing
    # at the actual cause (see Bug #2, tutorial 03).
    declared_chains = MapSet.new(Enum.map(t.chains, & &1.name))

    # Per Spec §7 (block-scoped jump resolution): a chain-rule jump/goto
    # whose target is not a chain declared in *this same block* is a
    # hard CompileError. Each TableBuilder is one block; same-owner
    # different-block does not share visibility. The diagnostic names
    # §4.4 because that is the wire-format reason — nft jumps cannot
    # cross tables.
    Enum.each(t.chains, fn chain ->
      Enum.each(chain.rules, fn
        {:jump, %{to: target}} ->
          ensure_jump_target_in_block!(t, chain, :jump, target, declared_chains)

        {:goto, %{to: target}} ->
          ensure_jump_target_in_block!(t, chain, :goto, target, declared_chains)

        _ ->
          :ok
      end)
    end)

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

    t
  end

  # Block-scoped jump-target resolver. Raises with §4.4 reference
  # so the operator gets the wire-format reason, not the misleading
  # "is not a defined chain" diagnostic the global pool would emit.
  defp ensure_jump_target_in_block!(table, chain, kind, target, declared_chains) do
    target_str = to_string(target)

    unless MapSet.member?(declared_chains, target_str) do
      raise CompileError,
        description:
          "nft_table #{inspect(table.name)} (owner #{inspect(table.owner)}): " <>
            "chain #{inspect(chain.name)} has rule #{inspect(kind)} " <>
            "target #{inspect(target_str)} which is not a chain in this block. " <>
            "Jumps and gotos are block-scoped (Spec §7); they cannot cross " <>
            "tables (nft wire format §4.4 — NFT_VERDICT_JUMP carries no " <>
            "table reference). Declared chains in this block: " <>
            inspect(MapSet.to_list(declared_chains)) <>
            ". If the target lives in a different owner block, declare it " <>
            "in this block instead — same-owner different-block does not " <>
            "share visibility."
    end
  end

  # Check a flat list of names for duplicates and raise a named
  # CompileError. Used for collections whose entries are bare strings
  # (counters) or where the :name field has already been projected.
  defp ensure_unique_names!(names, context) do
    dupes = names -- Enum.uniq(names)

    if dupes != [] do
      raise CompileError,
        description: "duplicate #{context}: #{inspect(Enum.uniq(dupes))}"
    end

    :ok
  end

  # Sets are stored as tuples — either {name, type} or {name, type, meta}
  # depending on whether any meta options were supplied. Project just the
  # name.
  defp set_names(sets) do
    Enum.map(sets, fn
      {name, _type} -> name
      {name, _type, _meta} -> name
    end)
  end

  @spec to_term(t()) :: map()
  def to_term(%__MODULE__{} = t) do
    base = %{
      family: t.family,
      name: t.name,
      owner: t.owner,
      counters: t.counters,
      chains: Enum.map(t.chains, &Erlkoenig.Nft.ChainBuilder.to_term/1)
    }

    base = if t.sets != [], do: Map.put(base, :sets, t.sets), else: base
    base = if t.maps != [], do: Map.put(base, :maps, t.maps), else: base
    base = if t.vmaps != [], do: Map.put(base, :vmaps, t.vmaps), else: base
    base = if t.flowtables != [], do: Map.put(base, :flowtables, t.flowtables), else: base
    base = if t.nflog_groups != [], do: Map.put(base, :nflog_groups, t.nflog_groups), else: base
    base
  end

  defp ensure_declared_nflog_group!(table, declared_groups, group)
       when is_integer(group) and group >= 0 do
    unless MapSet.member?(declared_groups, group) do
      raise CompileError,
        description:
          "nft_table #{inspect(table.name)}: nft_rule references " <>
            "nflog_group #{inspect(group)} but this table does not declare " <>
            "`nft_nflog_group #{group}`"
    end
  end

  defp ensure_declared_nflog_group!(table, _declared_groups, group) do
    raise CompileError,
      description:
        "nft_table #{inspect(table.name)}: nflog_group must be a non-negative integer, " <>
          "got #{inspect(group)}"
  end
end
