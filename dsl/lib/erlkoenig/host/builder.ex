defmodule Erlkoenig.Host.Builder do
  @moduledoc """
  Accumulates host topology: interfaces, bridges, and firewall chains.

  The host block describes the machine — its interfaces, bridges,
  and the nftables chains that protect it and control forwarding.
  """

  defstruct interfaces: [],
            bridges: [],
            chains: [],
            rules_acc: []

  def new, do: %__MODULE__{}

  # --- Interfaces ---

  def add_interface(%__MODULE__{interfaces: ifs} = h, name, opts) do
    iface = %{
      name: to_string(name),
      zone: Keyword.get(opts, :zone)
    }
    %{h | interfaces: ifs ++ [iface]}
  end

  # --- Bridges ---

  def add_bridge(%__MODULE__{bridges: brs} = h, name, opts) do
    {subnet, netmask} = case Keyword.fetch!(opts, :subnet) do
      {a, b, c, d, mask} -> {{a, b, c, d}, mask}
      {a, b, c, d} -> {{a, b, c, d}, 24}
    end
    {sa, sb, sc, _} = subnet

    bridge = %{
      name: to_string(name),
      subnet: subnet,
      netmask: netmask,
      gateway: Keyword.get(opts, :gateway, {sa, sb, sc, 1}),
      uplink: Keyword.get(opts, :uplink) && to_string(Keyword.get(opts, :uplink))
    }
    %{h | bridges: brs ++ [bridge]}
  end

  # --- Chains ---

  def begin_chain(%__MODULE__{} = h, _name, _opts) do
    %{h | rules_acc: []}
  end

  def end_chain(%__MODULE__{} = h, name, opts) do
    chain = build_chain(name, opts, h.rules_acc)
    %{h | chains: h.chains ++ [chain], rules_acc: []}
  end

  def push_rule(%__MODULE__{} = h, rule) do
    %{h | rules_acc: h.rules_acc ++ [rule]}
  end

  defp build_chain(name, opts, rules) do
    base = %{name: name, rules: rules}
    base = if opts[:hook], do: Map.put(base, :hook, opts[:hook]), else: base
    base = if opts[:type], do: Map.put(base, :type, opts[:type]), else: base
    base = if opts[:priority], do: Map.put(base, :priority, opts[:priority]), else: base
    base = if opts[:policy], do: Map.put(base, :policy, opts[:policy]), else: base
    base
  end

  # --- Validation ---

  def validate!(%__MODULE__{} = h, pod_names, all_container_names) do
    # Validate bridge uplinks reference declared interfaces
    iface_names = Enum.map(h.interfaces, & &1.name)
    Enum.each(h.bridges, fn br ->
      if br.uplink && br.uplink not in iface_names do
        raise CompileError,
          description: "bridge #{inspect(br.name)}: uplink #{inspect(br.uplink)} " <>
            "is not a declared interface. Known: #{inspect(iface_names)}"
      end
    end)

    # Validate rule interface references
    bridge_names = Enum.map(h.bridges, & &1.name)
    valid_names = MapSet.new(iface_names ++ bridge_names ++ ["lo"] ++ all_container_names)

    Enum.each(h.chains, fn chain ->
      Enum.each(chain.rules, fn
        {:rule, _verdict, opts} when is_map(opts) ->
          check_iface_ref(opts, :iif, valid_names, pod_names)
          check_iface_ref(opts, :oif, valid_names, pod_names)
        _ -> :ok
      end)
    end)

    :ok
  end

  defp check_iface_ref(opts, key, valid_names, pod_names) do
    case Map.get(opts, key) do
      nil -> :ok
      name when is_binary(name) ->
        # Could be "eth0", "br0", "web.frontend", or "lo"
        # Pod-qualified names (pod.container) are checked separately
        base = name |> String.split(".") |> hd()
        unless MapSet.member?(valid_names, name) or
               MapSet.member?(valid_names, base) or
               base in pod_names do
          raise CompileError,
            description: "rule references unknown interface #{inspect(name)}. " <>
              "Known: #{inspect(MapSet.to_list(valid_names))}"
        end
      _ -> :ok
    end
  end

  # --- Term output ---

  def to_term(%__MODULE__{} = h) do
    term = %{}
    term = if h.interfaces != [],
      do: Map.put(term, :interfaces, h.interfaces),
      else: term
    term = if h.bridges != [],
      do: Map.put(term, :bridges, h.bridges),
      else: term
    term = if h.chains != [],
      do: Map.put(term, :chains, h.chains),
      else: term
    term
  end
end
