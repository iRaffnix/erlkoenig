#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule ErlkoenigNft.Firewall.Builder do
  @moduledoc """
  Pure functional builder for firewall configurations.

  Accumulates DSL calls into a map that can be serialized to an
  Erlang term compatible with `erlkoenig_nft`.
  """

  # --- Constructor ---

  def new(name \\ "default", opts \\ [])

  def new(name, opts) when is_binary(name) and is_list(opts) do
    owner = Keyword.get(opts, :owner, false)
    %{name: name, owner: owner, sets: [], vmaps: [], counters: [], quotas: [],
      chains: [], flowtables: [], meters: [], rules_acc: [],
      zones: [], zone_inputs: [], zone_forwards: [], zone_masquerades: []}
  end

  # --- Sets ---

  def add_set(state, name, type) when is_binary(name) and type in [:ipv4_addr, :ipv6_addr] do
    update_in(state, [:sets], &(&1 ++ [{name, type}]))
  end

  def add_set(state, name, type, opts) when is_binary(name) and type in [:ipv4_addr, :ipv6_addr] do
    timeout = Keyword.get(opts, :timeout)
    elements = Keyword.get(opts, :elements)

    meta =
      %{}
      |> then(fn m -> if timeout, do: Map.merge(m, %{flags: [:timeout], timeout: timeout}), else: m end)
      |> then(fn m -> if elements, do: Map.put(m, :elements, elements), else: m end)

    case meta do
      m when m == %{} -> update_in(state, [:sets], &(&1 ++ [{name, type}]))
      m -> update_in(state, [:sets], &(&1 ++ [{name, type, m}]))
    end
  end

  @doc """
  Add a concatenated set. Fields is a list of type atoms.

  Example:
      add_concat_set(state, "allowpairs", [:ipv4_addr, :inet_service])
  """
  def add_concat_set(state, name, fields) when is_binary(name) and is_list(fields) do
    update_in(state, [:sets], &(&1 ++ [{name, :concat, %{fields: fields}}]))
  end

  def add_concat_set(state, name, fields, opts) when is_binary(name) and is_list(fields) do
    timeout = Keyword.get(opts, :timeout)
    base = %{fields: fields}
    meta = if timeout, do: Map.merge(base, %{flags: [:timeout], timeout: timeout}), else: base
    update_in(state, [:sets], &(&1 ++ [{name, :concat, meta}]))
  end

  # --- Verdict Maps ---

  @doc """
  Add a verdict map with initial entries.

  Entries is a list of {key, verdict} tuples where verdict is
  :accept, :drop, {:jump, chain}, or {:goto, chain}.

  In the DSL, keyword syntax is used: {80, jump: "http_chain"}
  """
  def add_vmap(state, name, type, opts) when is_binary(name) and is_list(opts) do
    entries = Keyword.fetch!(opts, :entries)
    normalized = Enum.map(entries, &normalize_vmap_entry/1)
    vmap = %{name: name, type: type, entries: normalized}
    update_in(state, [:vmaps], &(&1 ++ [vmap]))
  end

  defp normalize_vmap_entry({key, [jump: chain]}), do: {key, {:jump, chain}}
  defp normalize_vmap_entry({key, [goto: chain]}), do: {key, {:goto, chain}}
  defp normalize_vmap_entry({key, :accept}), do: {key, :accept}
  defp normalize_vmap_entry({key, :drop}), do: {key, :drop}
  defp normalize_vmap_entry({key, verdict}), do: {key, verdict}

  # --- Counters ---

  def add_counters(state, names) when is_list(names) do
    %{state | counters: state.counters ++ Enum.map(names, &to_string/1)}
  end

  # --- Quotas ---

  def add_quota(state, name, bytes, opts \\ []) when is_integer(bytes) do
    name = if is_atom(name), do: Atom.to_string(name), else: name
    mode = Keyword.get(opts, :mode, :until)
    flags = if mode == :over, do: 1, else: 0
    quota = %{name: name, bytes: bytes, flags: flags}
    update_in(state, [:quotas], &(&1 ++ [quota]))
  end

  # --- Chains ---

  def add_chain(state, name, opts, rules) when is_binary(name) and is_list(rules) do
    chain = case Keyword.get(opts, :hook) do
      nil ->
        # Regular chain (no hook) — used for jump targets
        base = %{name: name, rules: rules}
        if Keyword.has_key?(opts, :policy),
          do: Map.put(base, :policy, Keyword.get(opts, :policy)),
          else: base

      hook ->
        %{
          name: name,
          hook: hook,
          type: Keyword.get(opts, :type, :filter),
          priority: Keyword.get(opts, :priority, 0),
          policy: Keyword.fetch!(opts, :policy),
          rules: rules
        }
    end

    update_in(state, [:chains], &(&1 ++ [chain]))
  end

  # --- Rule constructors ---

  def ct_established_accept, do: :ct_established_accept
  def icmp_accept, do: :icmp_accept
  def accept, do: :accept

  def tcp_accept(port) when is_integer(port), do: {:tcp_accept, port}

  def tcp_accept(port, opts) when is_integer(port) and is_list(opts) do
    counter = Keyword.get(opts, :counter)
    limit = Keyword.get(opts, :limit)
    build_tcp_accept(port, counter, limit)
  end

  defp build_tcp_accept(port, nil, nil), do: {:tcp_accept, port}
  defp build_tcp_accept(port, counter, nil), do: {:tcp_accept, port, to_string(counter)}

  defp build_tcp_accept(port, counter, {rate, burst_opts}) do
    burst = if is_list(burst_opts), do: Keyword.fetch!(burst_opts, :burst), else: burst_opts
    c = if counter, do: to_string(counter), else: "tcp_#{port}"
    {:tcp_accept_limited, port, c, %{rate: rate, burst: burst}}
  end

  def tcp_port_range_accept(from, to_port), do: {:tcp_port_range_accept, from, to_port}
  def tcp_reject(port), do: {:tcp_reject, port}

  def udp_accept(port) when is_integer(port), do: {:udp_accept, port}

  def udp_accept(port, opts) when is_integer(port) and is_list(opts) do
    case Keyword.get(opts, :counter) do
      nil -> {:udp_accept, port}
      counter -> {:udp_accept, port, to_string(counter)}
    end
  end

  def udp_port_range_accept(from, to_port), do: {:udp_port_range_accept, from, to_port}

  def protocol_accept(proto), do: {:protocol_accept, proto}

  def ip_saddr_accept(ip), do: {:ip_saddr_accept, ip}
  def ip_saddr_drop(ip), do: {:ip_saddr_drop, ip}

  def iifname_accept(name), do: {:iifname_accept, name}
  def oifname_accept(name), do: {:oifname_accept, name}
  def oifname_neq_masq(name), do: {:oifname_neq_masq, name}
  def masquerade, do: :masq
  def forward_established, do: :forward_established

  def set_lookup_drop(set_name), do: {:set_lookup_drop, set_name}
  def set_lookup_drop(set_name, counter), do: {:set_lookup_drop, set_name, to_string(counter)}

  def connlimit_drop(max), do: {:connlimit_drop, max, 1}
  def connlimit_drop(max, offset), do: {:connlimit_drop, max, offset}

  def log_drop(prefix), do: {:log_drop, prefix}
  def log_drop(prefix, counter), do: {:log_drop, prefix, to_string(counter)}

  def log_reject(prefix), do: {:log_reject, prefix}

  def fib_rpf_drop, do: :fib_rpf_drop

  def synproxy_filter(port, opts) when is_integer(port) and is_list(opts) do
    mss = Keyword.get(opts, :mss, 1460)
    wscale = Keyword.get(opts, :wscale, 7)
    ts = if Keyword.get(opts, :timestamp, false), do: 1, else: 0
    sack = if Keyword.get(opts, :sack_perm, false), do: 2, else: 0
    {:synproxy, port, mss, wscale, Bitwise.bor(ts, sack)}
  end

  def nflog_capture_udp(port, prefix, group), do: {:nflog_capture_udp, port, prefix, group}
  def set_lookup_udp_accept(set_name, port), do: {:set_lookup_udp_accept, set_name, port}
  def log_drop_nflog(prefix, group, counter), do: {:log_drop_nflog, prefix, group, to_string(counter)}

  def notrack_rule(port, proto), do: {:notrack, port, proto}

  def meter_limit(name, port, proto, opts) when is_binary(name) and is_integer(port) do
    {:meter_limit, name, port, proto, opts}
  end

  def queue_rule(port, proto, opts), do: {:queue_rule, port, proto, opts}

  def cgroup_accept(cgroup_id), do: {:cgroup_accept, cgroup_id}
  def cgroup_drop(cgroup_id), do: {:cgroup_drop, cgroup_id}
  def ct_mark_set(value) when is_integer(value), do: {:ct_mark_set, value}
  def ct_mark_match(value, verdict) when is_integer(value), do: {:ct_mark_match, value, verdict}
  def osf_match(os_name, verdict), do: {:osf_match, os_name, verdict}

  def dnat(ip, port), do: {:dnat, ip, port}
  def tcp_dnat(match_port, dst_ip, dst_port), do: {:tcp_dnat, match_port, dst_ip, dst_port}
  def snat(ip, port), do: {:snat, ip, port}

  def vmap_dispatch(proto, vmap_name) when proto in [:tcp, :udp] and is_binary(vmap_name) do
    {:vmap_dispatch, proto, vmap_name}
  end

  # --- Meters (dynamic per-key rate limiting) ---

  @doc """
  Add a named meter (dynamic set with embedded limit).

  In nft: `meter "name" { ip saddr limit rate 5/second burst 3 }`

  Options:
    key: :saddr           — per source IP (default)
    limit: {rate, burst: N}
  """
  def add_meter(state, name, opts) when is_binary(name) and is_list(opts) do
    key = Keyword.get(opts, :key, :saddr)
    {rate, burst_opts} = Keyword.fetch!(opts, :limit)
    burst = if is_list(burst_opts), do: Keyword.fetch!(burst_opts, :burst), else: burst_opts
    meter = %{name: name, key: key, rate: rate, burst: burst}
    update_in(state, [:meters], fn
      nil -> [meter]
      meters -> meters ++ [meter]
    end)
  end

  # --- Flowtables ---

  def add_flowtable(state, name, opts) when is_binary(name) and is_list(opts) do
    ft = %{
      name: name,
      hook: Keyword.get(opts, :hook, :ingress),
      priority: Keyword.get(opts, :priority, 0),
      devices: Keyword.get(opts, :devices, []),
      flags: Keyword.get(opts, :flags, 0)
    }

    update_in(state, [:flowtables], &(&1 ++ [ft]))
  end

  def flow_offload(flowtable_name) when is_binary(flowtable_name) do
    {:flow_offload, flowtable_name}
  end
  def concat_set_lookup(set_name, fields, verdict),
    do: {:concat_set_lookup, set_name, fields, verdict}

  def accept_if_in_concat_set(set_name, fields),
    do: {:concat_set_lookup, set_name, fields, :accept}

  def drop_if_in_concat_set(set_name, fields),
    do: {:concat_set_lookup, set_name, fields, :drop}

  # --- Zone accumulators ---

  def add_zone(state, name, opts) when is_binary(name) do
    interfaces = Keyword.fetch!(opts, :interfaces)
    update_in(state, [:zones], &(&1 ++ [{name, interfaces}]))
  end

  def add_zone_input(state, zone_name, policy, rules) do
    update_in(state, [:zone_inputs], &(&1 ++ [{zone_name, policy, rules}]))
  end

  def add_zone_forward(state, from, to, policy, rules) do
    update_in(state, [:zone_forwards], &(&1 ++ [{from, to, policy, rules}]))
  end

  def add_zone_masquerade(state, from, to) do
    update_in(state, [:zone_masquerades], &(&1 ++ [{from, to}]))
  end

  # --- Generic rule builder ---

  @doc """
  Build a generic rule from a verdict and keyword options.

  Options:
    ct: :established         — match conntrack state
    iif: "name"              — match input interface (wildcard ok)
    oif: "name"              — match output interface (wildcard ok)
    oif_neq: "name"          — match output interface NOT equal
    icmp: true               — match ICMP protocol
    tcp: port                — match TCP destination port
    udp: port                — match UDP destination port
    saddr: {a,b,c,d,prefix}  — match source IP/subnet
    daddr: {a,b,c,d,prefix}  — match destination IP/subnet
    set: "name"              — match against named set (ip saddr @name)
    log: "prefix"            — log with prefix before verdict
    limit: {rate, burst: n}  — rate limit
    counter: :name           — count packets/bytes

  Returns an Erlang term tuple understood by erlkoenig_firewall_nft:compile_rule/1.
  """
  def build_rule(verdict, opts) when is_atom(verdict) and is_list(opts) do
    {:rule, verdict, Map.new(opts, fn
      {k, v} when is_atom(k) -> {k, normalize_rule_opt(k, v)}
    end)}
  end

  # -- Matches (read kernel state) --
  defp normalize_rule_opt(:iif, {:ref, name}), do: {:ref, to_string(name)}
  defp normalize_rule_opt(:iif, :bridge), do: :bridge
  defp normalize_rule_opt(:iif, v), do: to_string(v)
  defp normalize_rule_opt(:oif, {:ref, name}), do: {:ref, to_string(name)}
  defp normalize_rule_opt(:oif, :bridge), do: :bridge
  defp normalize_rule_opt(:oif, :containers), do: :containers
  defp normalize_rule_opt(:oif, v), do: to_string(v)
  defp normalize_rule_opt(:oif_neq, v), do: to_string(v)
  defp normalize_rule_opt(:set, v), do: to_string(v)
  defp normalize_rule_opt(:saddr, {a, b, c, d, prefix}), do: {a, b, c, d, prefix}
  defp normalize_rule_opt(:saddr, {a, b, c, d}), do: {a, b, c, d, 32}
  defp normalize_rule_opt(:daddr, {a, b, c, d, prefix}), do: {a, b, c, d, prefix}
  defp normalize_rule_opt(:daddr, {a, b, c, d}), do: {a, b, c, d, 32}
  defp normalize_rule_opt(:ct_mark, v) when is_integer(v), do: v
  defp normalize_rule_opt(:fib, :rpf), do: :rpf
  defp normalize_rule_opt(:vmap, v), do: to_string(v)
  defp normalize_rule_opt(:quota, v), do: to_string(v)
  defp normalize_rule_opt(:meter, v), do: to_string(v)

  # -- Statements (write / side-effects) --
  defp normalize_rule_opt(:counter, v) when is_atom(v), do: to_string(v)
  defp normalize_rule_opt(:counter, v) when is_binary(v), do: v
  defp normalize_rule_opt(:log, v), do: to_string(v)
  defp normalize_rule_opt(:nflog, v) when is_integer(v), do: v
  defp normalize_rule_opt(:ct_mark_set, v) when is_integer(v), do: v
  defp normalize_rule_opt(:limit, {rate, burst_opts}) when is_list(burst_opts) do
    %{rate: rate, burst: Keyword.fetch!(burst_opts, :burst)}
  end
  defp normalize_rule_opt(:limit, {rate, burst}) when is_integer(burst) do
    %{rate: rate, burst: burst}
  end
  defp normalize_rule_opt(:flowtable, v), do: to_string(v)
  defp normalize_rule_opt(:chain, v), do: to_string(v)

  defp normalize_rule_opt(_, v), do: v

  # --- Rule accumulator (used by chain macro) ---

  def push_rule(state, rule) do
    update_in(state, [:rules_acc], &(&1 ++ [rule]))
  end

  @doc "Push a rule and auto-register any counter it references."
  def push_rule_with_counter(state, rule) do
    state = push_rule(state, rule)
    case extract_counter(rule) do
      nil -> state
      name ->
        if name in state.counters, do: state, else: add_counters(state, [name])
    end
  end

  defp extract_counter({_, _, counter, _}) when is_binary(counter), do: counter
  defp extract_counter({_, _, counter}) when is_binary(counter), do: counter
  defp extract_counter(_), do: nil

  def take_rules(state) do
    {state.rules_acc, %{state | rules_acc: []}}
  end

  # --- Serialization ---

  def to_term(state) do
    state = expand_zones(state)
    validate_jump_targets!(state)

    base = %{
      table: state.name,
      chains: Enum.map(state.chains, &chain_to_term/1)
    }

    base = if state.owner, do: Map.put(base, :owner, true), else: base
    base = if state.sets != [], do: Map.put(base, :sets, state.sets), else: base
    base = if state.vmaps != [], do: Map.put(base, :vmaps, state.vmaps), else: base
    base = if state.counters != [], do: Map.put(base, :counters, state.counters), else: base
    base = if state.flowtables != [], do: Map.put(base, :flowtables, state.flowtables), else: base
    base = if state.quotas != [], do: Map.put(base, :quotas, state.quotas), else: base
    base = if state.meters != [], do: Map.put(base, :meters, state.meters), else: base
    base
  end

  def write!(state, path) do
    term = to_term(state)
    formatted = :io_lib.format(~c"~tp.~n", [term])
    File.write!(path, formatted)
  end

  defp chain_to_term(chain) do
    case Map.get(chain, :hook) do
      nil ->
        %{name: chain.name, rules: chain.rules}

      hook ->
        %{
          name: chain.name,
          hook: hook,
          type: Map.get(chain, :type, :filter),
          priority: Map.get(chain, :priority, 0),
          policy: Map.get(chain, :policy, :accept),
          rules: chain.rules
        }
    end
  end

  # --- Zone expansion ---

  defp expand_zones(%{zones: []} = state), do: state

  defp expand_zones(state) do
    validate_zones!(state)

    zone_map = Map.new(state.zones)
    zone_chains = []

    # 1. z_dispatch_input — base chain (hook: input, policy: drop)
    #    Zones with zone_input get a jump; zones without get iifname_accept
    #    (implicitly trusted — no filtering configured means accept all).
    configured_zones = MapSet.new(Enum.map(state.zone_inputs, &elem(&1, 0)))

    input_dispatch_rules =
      [:ct_established_accept, {:iifname_accept, "lo"}] ++
        Enum.flat_map(state.zones, fn {zone_name, interfaces} ->
          if MapSet.member?(configured_zones, zone_name) do
            Enum.map(interfaces, fn iface ->
              {:iifname_jump, iface, "z_input_#{zone_name}"}
            end)
          else
            # Zone without zone_input — accept all traffic from its interfaces
            Enum.map(interfaces, fn iface ->
              {:iifname_accept, iface}
            end)
          end
        end)

    zone_chains =
      zone_chains ++
        [
          %{
            name: "z_dispatch_input",
            hook: :input,
            type: :filter,
            priority: 0,
            policy: :drop,
            rules: input_dispatch_rules
          }
        ]

    # 2. z_input_<zone> — regular chains
    zone_chains =
      zone_chains ++
        Enum.map(state.zone_inputs, fn {zone_name, policy, rules} ->
          final_rules =
            if policy == :accept, do: rules ++ [:accept], else: rules

          %{name: "z_input_#{zone_name}", rules: final_rules}
        end)

    # 3. z_dispatch_forward — base chain (hook: forward, policy: drop)
    has_forwards = state.zone_forwards != []

    zone_chains =
      if has_forwards do
        forward_dispatch_rules =
          [:ct_established_accept] ++
            Enum.flat_map(state.zone_forwards, fn {from, to, _policy, _rules} ->
              in_ifaces = Map.fetch!(zone_map, from)
              out_ifaces = Map.fetch!(zone_map, to)

              for in_if <- in_ifaces, out_if <- out_ifaces do
                {:iifname_oifname_jump, in_if, out_if, "z_fwd_#{from}_#{to}"}
              end
            end)

        zone_chains ++
          [
            %{
              name: "z_dispatch_forward",
              hook: :forward,
              type: :filter,
              priority: 0,
              policy: :drop,
              rules: forward_dispatch_rules
            }
          ]
      else
        zone_chains
      end

    # 4. z_fwd_<from>_<to> — regular chains
    zone_chains =
      zone_chains ++
        Enum.map(state.zone_forwards, fn {from, to, policy, rules} ->
          final_rules =
            if policy == :accept, do: rules ++ [:accept], else: rules

          %{name: "z_fwd_#{from}_#{to}", rules: final_rules}
        end)

    # 5. z_nat_postrouting — base chain for masquerade
    zone_chains =
      if state.zone_masquerades != [] do
        nat_rules =
          Enum.flat_map(state.zone_masquerades, fn {from, to} ->
            in_ifaces = Map.fetch!(zone_map, from)
            out_ifaces = Map.fetch!(zone_map, to)

            for in_if <- in_ifaces, out_if <- out_ifaces do
              {:iifname_oifname_masq, in_if, out_if}
            end
          end)

        zone_chains ++
          [
            %{
              name: "z_nat_postrouting",
              hook: :postrouting,
              type: :nat,
              priority: 100,
              policy: :accept,
              rules: nat_rules
            }
          ]
      else
        zone_chains
      end

    # Prepend zone chains before manual chains
    %{state | chains: zone_chains ++ state.chains}
  end

  defp validate_zones!(state) do
    zone_names = Enum.map(state.zones, &elem(&1, 0))

    # Check for duplicate zone names
    case zone_names -- Enum.uniq(zone_names) do
      [] -> :ok
      dups -> raise "Duplicate zone names: #{inspect(Enum.uniq(dups))}"
    end

    # Check for duplicate interfaces across zones
    all_ifaces =
      Enum.flat_map(state.zones, fn {name, ifaces} ->
        Enum.map(ifaces, &{&1, name})
      end)

    iface_names = Enum.map(all_ifaces, &elem(&1, 0))

    case iface_names -- Enum.uniq(iface_names) do
      [] ->
        :ok

      dup_ifaces ->
        dup_ifaces = Enum.uniq(dup_ifaces)

        zones_with_dup =
          Enum.filter(all_ifaces, fn {iface, _} -> iface in dup_ifaces end)

        raise "Interface(s) assigned to multiple zones: #{inspect(zones_with_dup)}"
    end

    # Check zone_input references
    Enum.each(state.zone_inputs, fn {zone_name, _, _} ->
      unless zone_name in zone_names do
        raise "zone_input references undefined zone: #{inspect(zone_name)}"
      end
    end)

    # Check zone_forward references
    Enum.each(state.zone_forwards, fn {from, to, _, _} ->
      unless from in zone_names do
        raise "zone_forward references undefined zone: #{inspect(from)}"
      end

      unless to in zone_names do
        raise "zone_forward references undefined zone: #{inspect(to)}"
      end
    end)

    # Check zone_masquerade references
    Enum.each(state.zone_masquerades, fn {from, to} ->
      unless from in zone_names do
        raise "zone_masquerade references undefined zone: #{inspect(from)}"
      end

      unless to in zone_names do
        raise "zone_masquerade references undefined zone: #{inspect(to)}"
      end
    end)
  end

  # Validate that all jump/goto targets in vmaps and rules reference
  # chains that are actually defined. Catches dangling references at
  # compile time instead of crashing the firewall at boot with {-2, enoent}.
  defp validate_jump_targets!(state) do
    chain_names =
      state.chains
      |> Enum.map(fn c -> c[:name] || c.name end)
      |> MapSet.new()

    # Check vmap entries
    Enum.each(state.vmaps, fn vmap ->
      vmap_name = vmap[:name] || vmap.name
      entries = vmap[:entries] || vmap.entries || []

      Enum.each(entries, fn
        {_key, {:jump, target}} ->
          target_str = to_string(target)
          unless MapSet.member?(chain_names, target_str) do
            raise "vmap #{inspect(vmap_name)}: jump target #{inspect(target_str)} " <>
                    "is not a defined chain. " <>
                    "Defined chains: #{inspect(MapSet.to_list(chain_names))}"
          end

        {_key, {:goto, target}} ->
          target_str = to_string(target)
          unless MapSet.member?(chain_names, target_str) do
            raise "vmap #{inspect(vmap_name)}: goto target #{inspect(target_str)} " <>
                    "is not a defined chain. " <>
                    "Defined chains: #{inspect(MapSet.to_list(chain_names))}"
          end

        _ ->
          :ok
      end)
    end)

    # Check jump/goto rules in chains
    Enum.each(state.chains, fn chain ->
      chain_name = chain[:name] || chain.name
      rules = chain[:rules] || chain.rules || []

      Enum.each(rules, fn
        {:jump, target} ->
          target_str = to_string(target)
          unless MapSet.member?(chain_names, target_str) do
            raise "chain #{inspect(chain_name)}: jump target #{inspect(target_str)} " <>
                    "is not a defined chain. " <>
                    "Defined chains: #{inspect(MapSet.to_list(chain_names))}"
          end

        {:goto, target} ->
          target_str = to_string(target)
          unless MapSet.member?(chain_names, target_str) do
            raise "chain #{inspect(chain_name)}: goto target #{inspect(target_str)} " <>
                    "is not a defined chain. " <>
                    "Defined chains: #{inspect(MapSet.to_list(chain_names))}"
          end

        {:iifname_jump, _iface, target} ->
          target_str = to_string(target)
          unless MapSet.member?(chain_names, target_str) do
            raise "chain #{inspect(chain_name)}: iifname_jump target #{inspect(target_str)} " <>
                    "is not a defined chain. " <>
                    "Defined chains: #{inspect(MapSet.to_list(chain_names))}"
          end

        {:iifname_oifname_jump, _in, _out, target} ->
          target_str = to_string(target)
          unless MapSet.member?(chain_names, target_str) do
            raise "chain #{inspect(chain_name)}: iifname_oifname_jump target #{inspect(target_str)} " <>
                    "is not a defined chain. " <>
                    "Defined chains: #{inspect(MapSet.to_list(chain_names))}"
          end

        _ ->
          :ok
      end)
    end)
  end
end
