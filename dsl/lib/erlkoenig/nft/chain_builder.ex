#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0

defmodule Erlkoenig.Nft.ChainBuilder do
  @moduledoc """
  Accumulates chain definitions: rules with match fields and actions.

  Two types:
  - Base chain: has hook, type, priority, policy (attached to netfilter)
  - Regular chain: jump target, implicit return at end
  """

  defstruct name: nil,
            # :base or :regular
            type: :regular,
            hook: nil,
            # :filter, :nat, :route
            chain_type: nil,
            # :filter, :dstnat, :srcnat, or integer
            priority: nil,
            # :accept, :drop
            policy: nil,
            rules: [],
            # Spec §7 owner-model: chains do not accept an owner
            # argument from the operator. The TableBuilder stamps
            # owner during the add_chain finalization pass.
            owner: nil

  @valid_hooks [:input, :output, :forward, :prerouting, :postrouting]
  @valid_types [:filter, :nat, :route]
  @valid_priorities [:filter, :dstnat, :srcnat, :mangle, :security, :raw]
  @valid_policies [:accept, :drop]
  @valid_actions [
    :accept,
    :drop,
    :return,
    :jump,
    :masquerade,
    :reject,
    :notrack,
    :ct_mark_set,
    :ct_mark_match,
    :snat,
    :dnat,
    :dnat_lb,
    :dnat_jhash,
    :flow_offload,
    :fib_rpf,
    :connlimit_drop,
    :vmap_dispatch,
    :vmap_lookup
  ]

  @type t :: %__MODULE__{
          name: String.t() | atom() | nil,
          type: :base | :regular,
          hook: atom() | nil,
          chain_type: atom() | nil,
          priority: atom() | integer() | nil,
          policy: atom() | nil,
          rules: list(),
          owner: atom() | nil
        }

  @spec new_base(String.t() | atom(), keyword()) :: t()
  def new_base(name, opts) do
    hook = Keyword.fetch!(opts, :hook)
    type = Keyword.fetch!(opts, :type)
    priority = Keyword.fetch!(opts, :priority)
    policy = Keyword.fetch!(opts, :policy)

    unless hook in @valid_hooks do
      raise CompileError,
        description: "base_chain #{inspect(name)}: invalid hook #{inspect(hook)}"
    end

    unless type in @valid_types do
      raise CompileError,
        description: "base_chain #{inspect(name)}: invalid type #{inspect(type)}"
    end

    unless priority in @valid_priorities or is_integer(priority) do
      raise CompileError,
        description: "base_chain #{inspect(name)}: invalid priority #{inspect(priority)}"
    end

    unless policy in @valid_policies do
      raise CompileError,
        description: "base_chain #{inspect(name)}: invalid policy #{inspect(policy)}"
    end

    %__MODULE__{
      name: name,
      type: :base,
      hook: hook,
      chain_type: type,
      priority: priority,
      policy: policy
    }
  end

  @spec new_regular(String.t() | atom()) :: t()
  def new_regular(name) do
    %__MODULE__{name: name, type: :regular}
  end

  @spec add_rule(t(), atom(), keyword()) :: t()
  def add_rule(%__MODULE__{rules: rs} = c, action, opts) when is_list(opts) do
    unless action in @valid_actions do
      raise CompileError,
        description: "chain #{inspect(c.name)}: invalid action #{inspect(action)}"
    end

    if action == :jump and not Keyword.has_key?(opts, :to) do
      raise CompileError, description: "chain #{inspect(c.name)}: rule :jump requires :to option"
    end

    %{c | rules: rs ++ [{action, Map.new(opts)}]}
  end

  # --- conn_limit sugar -------------------------------------------
  #
  # `conn_limit per_ip: N` expands to a plain `nft_rule
  # :connlimit_drop, max: N`. The sugar exists only to give the
  # operator a short, typed form with a compile-time integer check.
  # Zero synthesis beyond that — the resulting rule lives in the
  # chain's rule list exactly where it was written.

  def add_conn_limit(%__MODULE__{} = chain, opts) when is_list(opts) do
    {action, rule_opts} = compile_conn_limit!(opts)
    add_rule(chain, action, rule_opts)
  end

  @spec validate!(t()) :: t()
  def validate!(%__MODULE__{} = chain), do: chain

  @spec to_term(t()) :: map()
  def to_term(%__MODULE__{type: :base} = chain) do
    %{
      name: chain.name,
      owner: chain.owner,
      hook: chain.hook,
      type: chain.chain_type,
      priority: chain.priority,
      policy: chain.policy,
      rules: chain.rules
    }
  end

  def to_term(%__MODULE__{} = chain) do
    %{
      name: chain.name,
      owner: chain.owner,
      rules: chain.rules
    }
  end

  @doc false
  # Shared validator used by both chain paths (Stack container-inline
  # via Pod.Builder, and Stack table-level via this module).
  def compile_conn_limit!(opts) when is_list(opts) do
    reject_deprecated!(opts)

    case Keyword.get(opts, :per_ip) do
      n when is_integer(n) and n > 0 ->
        {:connlimit_drop, [max: n]}

      nil ->
        raise CompileError,
          description:
            "conn_limit needs :per_ip with a positive integer " <>
              "(got #{inspect(opts)})"

      other ->
        raise CompileError,
          description:
            "conn_limit :per_ip must be a positive integer, got " <>
              inspect(other)
    end
  end

  # `global:` and `audit:` lived in the previous design. Reject both
  # loudly so in-flight stack files are found, not silently accepted.
  defp reject_deprecated!(opts) do
    Enum.each([:global, :audit], fn key ->
      if Keyword.has_key?(opts, key) do
        raise CompileError,
          description:
            "conn_limit #{inspect(key)}: option removed — see " <>
              "SPEC-EK-028 §3. Remove the option from your stack file."
      end
    end)
  end
end
