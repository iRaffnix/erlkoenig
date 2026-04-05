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
            type: :regular,   # :base or :regular
            hook: nil,
            chain_type: nil,  # :filter, :nat, :route
            priority: nil,    # :filter, :dstnat, :srcnat, or integer
            policy: nil,      # :accept, :drop
            rules: []

  @valid_hooks [:input, :output, :forward, :prerouting, :postrouting]
  @valid_types [:filter, :nat, :route]
  @valid_priorities [:filter, :dstnat, :srcnat, :mangle, :security, :raw]
  @valid_policies [:accept, :drop]
  @valid_actions [:accept, :drop, :return, :jump, :masquerade, :reject,
                  :notrack, :ct_mark_set, :ct_mark_match, :snat, :dnat,
                  :fib_rpf, :connlimit_drop, :vmap_dispatch]

  def new_base(name, opts) do
    hook = Keyword.fetch!(opts, :hook)
    type = Keyword.fetch!(opts, :type)
    priority = Keyword.fetch!(opts, :priority)
    policy = Keyword.fetch!(opts, :policy)

    unless hook in @valid_hooks do
      raise CompileError, description: "base_chain #{inspect(name)}: invalid hook #{inspect(hook)}"
    end
    unless type in @valid_types do
      raise CompileError, description: "base_chain #{inspect(name)}: invalid type #{inspect(type)}"
    end
    unless priority in @valid_priorities or is_integer(priority) do
      raise CompileError, description: "base_chain #{inspect(name)}: invalid priority #{inspect(priority)}"
    end
    unless policy in @valid_policies do
      raise CompileError, description: "base_chain #{inspect(name)}: invalid policy #{inspect(policy)}"
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

  def new_regular(name) do
    %__MODULE__{name: name, type: :regular}
  end

  def add_rule(%__MODULE__{rules: rs} = c, action, opts) when is_list(opts) do
    unless action in @valid_actions do
      raise CompileError, description: "chain #{inspect(c.name)}: invalid action #{inspect(action)}"
    end

    if action == :jump and not Keyword.has_key?(opts, :to) do
      raise CompileError, description: "chain #{inspect(c.name)}: rule :jump requires :to option"
    end

    %{c | rules: rs ++ [{action, Map.new(opts)}]}
  end
end
