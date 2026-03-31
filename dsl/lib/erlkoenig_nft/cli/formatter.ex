defmodule ErlkoenigNft.CLI.Formatter do
  @moduledoc """
  Renders firewall configs as nft-style rulesets with ANSI colors.
  """

  @colors %{
    bold: "\e[1m",
    dim: "\e[2m",
    green: "\e[32m",
    yellow: "\e[33m",
    blue: "\e[34m",
    cyan: "\e[36m",
    red: "\e[31m",
    reset: "\e[0m"
  }

  def color(name, text) do
    if IO.ANSI.enabled?() do
      "#{@colors[name]}#{text}#{@colors[:reset]}"
    else
      text
    end
  end

  # --- Firewall ---

  def render_firewall(config, mod) do
    IO.puts("")
    IO.puts(color(:bold, "# #{inspect(mod)}"))
    IO.puts(color(:bold, "table inet #{table_name(config)} {"))

    render_counters(config[:counters])
    render_sets(config[:sets])

    for chain <- config[:chains] || [] do
      render_chain(chain)
    end

    IO.puts(color(:bold, "}"))
    IO.puts("")
  end

  defp table_name(config) do
    cond do
      is_binary(config[:table]) -> config[:table]
      is_list(config[:chains]) and config[:chains] != [] ->
        "erlkoenig"
      true -> "erlkoenig"
    end
  end

  defp render_counters(nil), do: :ok
  defp render_counters([]), do: :ok

  defp render_counters(counters) do
    for c <- counters do
      IO.puts("    #{color(:dim, "counter")} #{color(:yellow, to_string(c))} { packets 0 bytes 0 }")
    end

    IO.puts("")
  end

  defp render_sets(nil), do: :ok
  defp render_sets([]), do: :ok

  defp render_sets(sets) do
    for s <- sets do
      {name, type, opts} = normalize_set(s)

      IO.puts("    #{color(:dim, "set")} #{color(:cyan, name)} {")
      IO.puts("        type #{format_set_type(type)}")

      if opts[:timeout] do
        IO.puts("        timeout #{format_duration(opts[:timeout])}")
      end

      IO.puts("    }")
    end

    IO.puts("")
  end

  defp normalize_set({name, type}), do: {name, type, %{}}
  defp normalize_set({name, type, opts}), do: {name, type, opts}

  defp format_set_type(:ipv4_addr), do: "ipv4_addr"
  defp format_set_type(:ipv6_addr), do: "ipv6_addr"
  defp format_set_type(other), do: to_string(other)

  defp render_chain(chain) do
    hook = chain[:hook]
    type = chain[:type] || :filter
    priority = chain[:priority] || 0
    policy = chain[:policy] || :accept

    IO.puts("    #{color(:dim, "chain")} #{color(:cyan, chain[:name])} {")
    IO.puts("        type #{type} hook #{hook} priority #{priority}; policy #{policy};")

    for rule <- chain[:rules] || [] do
      IO.puts("        #{format_rule(rule)}")
    end

    IO.puts("    }")
    IO.puts("")
  end

  defp format_rule(:ct_established_accept) do
    "#{kw("ct state")} established,related #{verdict(:accept)}"
  end

  defp format_rule(:icmp_accept) do
    "#{kw("meta l4proto")} { icmp, icmpv6 } #{verdict(:accept)}"
  end

  defp format_rule(:accept) do
    verdict(:accept)
  end

  defp format_rule({:iifname_accept, name}) do
    "#{kw("iifname")} #{color(:yellow, "\"#{name}\"")} #{verdict(:accept)}"
  end

  defp format_rule({:tcp_accept, port}) do
    "#{kw("tcp dport")} #{port} #{verdict(:accept)}"
  end

  defp format_rule({:tcp_accept, port, counter}) do
    "#{kw("tcp dport")} #{port} #{cnt(counter)} #{verdict(:accept)}"
  end

  defp format_rule({:tcp_accept_limited, port, counter, %{rate: rate, burst: burst}}) do
    "#{kw("tcp dport")} #{port} #{cnt(counter)} #{kw("limit rate")} #{rate}/second burst #{burst} packets #{verdict(:accept)}"
  end

  defp format_rule({:tcp_reject, port}) do
    "#{kw("tcp dport")} #{port} #{verdict(:reject)}"
  end

  defp format_rule({:tcp_port_range_accept, from, to}) do
    "#{kw("tcp dport")} #{from}-#{to} #{verdict(:accept)}"
  end

  defp format_rule({:udp_accept, port}) do
    "#{kw("udp dport")} #{port} #{verdict(:accept)}"
  end

  defp format_rule({:udp_accept, port, counter}) do
    "#{kw("udp dport")} #{port} #{cnt(counter)} #{verdict(:accept)}"
  end

  defp format_rule({:udp_accept_limited, port, counter, %{rate: rate, burst: burst}}) do
    "#{kw("udp dport")} #{port} #{cnt(counter)} #{kw("limit rate")} #{rate}/second burst #{burst} packets #{verdict(:accept)}"
  end

  defp format_rule({:udp_port_range_accept, from, to}) do
    "#{kw("udp dport")} #{from}-#{to} #{verdict(:accept)}"
  end

  defp format_rule({:protocol_accept, proto}) do
    "#{kw("meta l4proto")} #{proto} #{verdict(:accept)}"
  end

  defp format_rule({:ip_saddr_accept, ip}) do
    "#{kw("ip saddr")} #{format_ip(ip)} #{verdict(:accept)}"
  end

  defp format_rule({:ip_saddr_drop, ip}) do
    "#{kw("ip saddr")} #{format_ip(ip)} #{verdict(:drop)}"
  end

  defp format_rule({:set_lookup_drop, set_name}) do
    "#{kw("ip saddr")} @#{set_name} #{verdict(:drop)}"
  end

  defp format_rule({:set_lookup_drop, set_name, counter}) do
    "#{kw("ip saddr")} @#{set_name} #{cnt(counter)} #{verdict(:drop)}"
  end

  defp format_rule({:connlimit_drop, max, _offset}) do
    "#{kw("ct count over")} #{max} #{verdict(:drop)}"
  end

  defp format_rule({:log_drop, prefix}) do
    "#{kw("log prefix")} #{color(:yellow, "\"#{prefix}\"")} #{verdict(:drop)}"
  end

  defp format_rule({:log_drop, prefix, counter}) do
    "#{kw("log prefix")} #{color(:yellow, "\"#{prefix}\"")} #{cnt(counter)} #{verdict(:drop)}"
  end

  defp format_rule({:log_drop_nflog, prefix, group, counter}) do
    "#{kw("log prefix")} #{color(:yellow, "\"#{prefix}\"")} #{kw("group")} #{group} #{cnt(counter)} #{verdict(:drop)}"
  end

  defp format_rule({:log_reject, prefix}) do
    "#{kw("log prefix")} #{color(:yellow, "\"#{prefix}\"")} #{verdict(:reject)}"
  end

  defp format_rule({:dnat, ip, port}) do
    "#{kw("dnat to")} #{format_ip(ip)}:#{port}"
  end

  defp format_rule(:masq) do
    kw("masquerade")
  end

  defp format_rule({:set_lookup_udp_accept, set_name, port}) do
    "#{kw("ip saddr")} @#{set_name} #{kw("udp dport")} #{port} #{verdict(:accept)}"
  end

  defp format_rule({:nflog_capture_udp, port, prefix, group}) do
    "#{kw("udp dport")} #{port} #{kw("log prefix")} #{color(:yellow, "\"#{prefix}\"")} #{kw("group")} #{group} #{verdict(:drop)}"
  end

  defp format_rule(other) do
    color(:dim, "# #{inspect(other)}")
  end

  # --- Guard ---

  def render_guard(config, mod) do
    IO.puts("")
    IO.puts(color(:bold, "# #{inspect(mod)}"))
    IO.puts(color(:bold, "ct_guard {"))

    if config[:conn_flood] do
      {t, w} = config[:conn_flood]
      IO.puts("    #{kw("detect")} conn_flood  threshold #{t}  window #{w}s")
    end

    if config[:port_scan] do
      {t, w} = config[:port_scan]
      IO.puts("    #{kw("detect")} port_scan   threshold #{t}  window #{w}s")
    end

    IO.puts("    #{kw("ban_duration")} #{format_duration(config[:ban_duration] || 3600)}")

    for ip <- config[:whitelist] || [] do
      IO.puts("    #{kw("whitelist")} #{format_ip(ip)}")
    end

    IO.puts(color(:bold, "}"))
    IO.puts("")
  end

  # --- Watch ---

  def render_watch(config, mod) do
    IO.puts("")
    IO.puts(color(:bold, "# #{inspect(mod)}"))
    IO.puts(color(:bold, "watch #{config[:name] || "default"} {"))
    IO.puts("    #{kw("interval")} #{config[:interval] || 2000}ms")

    for t <- config[:thresholds] || [] do
      render_threshold(t)
    end

    for action <- config[:actions] || [] do
      case action do
        :log -> IO.puts("    #{kw("on_alert")} log")
        {:webhook, url} -> IO.puts("    #{kw("on_alert")} webhook #{color(:yellow, "\"#{url}\"")}")
        {:exec, cmd} -> IO.puts("    #{kw("on_alert")} exec #{color(:yellow, "\"#{cmd}\"")}")
        :isolate -> IO.puts("    #{kw("on_alert")} isolate")
      end
    end

    IO.puts(color(:bold, "}"))
    IO.puts("")
  end

  defp render_threshold({_id, counter, metric, op, value}) do
    IO.puts("    #{kw("alert")} #{counter} #{metric} #{op} #{value}")
  end

  defp render_threshold(%{counter: counter, metric: metric, op: op, value: value}) do
    IO.puts("    #{kw("alert")} #{counter} #{metric} #{op} #{value}")
  end

  # --- Diff ---

  def render_diff(config_a, config_b, name_a, name_b) do
    IO.puts("")
    IO.puts(color(:bold, "--- #{name_a}"))
    IO.puts(color(:bold, "+++ #{name_b}"))
    IO.puts("")

    diff_section("counters", config_a[:counters] || [], config_b[:counters] || [])
    diff_section("sets", normalize_sets(config_a[:sets] || []), normalize_sets(config_b[:sets] || []))
    diff_chains(config_a[:chains] || [], config_b[:chains] || [])
  end

  defp diff_section(label, list_a, list_b) do
    set_a = MapSet.new(list_a)
    set_b = MapSet.new(list_b)

    removed = MapSet.difference(set_a, set_b)
    added = MapSet.difference(set_b, set_a)

    if MapSet.size(removed) > 0 or MapSet.size(added) > 0 do
      IO.puts(color(:bold, "  #{label}:"))

      for item <- removed do
        IO.puts(color(:red, "    - #{inspect(item)}"))
      end

      for item <- added do
        IO.puts(color(:green, "    + #{inspect(item)}"))
      end

      IO.puts("")
    end
  end

  defp diff_chains(chains_a, chains_b) do
    names_a = MapSet.new(chains_a, & &1[:name])
    names_b = MapSet.new(chains_b, & &1[:name])
    all_names = MapSet.union(names_a, names_b) |> Enum.sort()

    map_a = Map.new(chains_a, &{&1[:name], &1})
    map_b = Map.new(chains_b, &{&1[:name], &1})

    for name <- all_names do
      chain_a = map_a[name]
      chain_b = map_b[name]

      cond do
        chain_a == nil ->
          IO.puts(color(:green, "  + chain #{name}"))
          for rule <- chain_b[:rules] || [] do
            IO.puts(color(:green, "    + #{format_rule(rule)}"))
          end
          IO.puts("")

        chain_b == nil ->
          IO.puts(color(:red, "  - chain #{name}"))
          for rule <- chain_a[:rules] || [] do
            IO.puts(color(:red, "    - #{format_rule(rule)}"))
          end
          IO.puts("")

        chain_a != chain_b ->
          IO.puts(color(:bold, "  chain #{name}:"))
          diff_chain_props(chain_a, chain_b)
          diff_rules(chain_a[:rules] || [], chain_b[:rules] || [])
          IO.puts("")

        true ->
          :ok
      end
    end
  end

  defp diff_chain_props(a, b) do
    for key <- [:hook, :type, :priority, :policy] do
      va = a[key]
      vb = b[key]

      if va != vb do
        IO.puts(color(:red, "    - #{key}: #{inspect(va)}"))
        IO.puts(color(:green, "    + #{key}: #{inspect(vb)}"))
      end
    end
  end

  defp diff_rules(rules_a, rules_b) do
    set_a = MapSet.new(rules_a)
    set_b = MapSet.new(rules_b)

    removed = MapSet.difference(set_a, set_b) |> Enum.to_list()
    added = MapSet.difference(set_b, set_a) |> Enum.to_list()

    for rule <- removed do
      IO.puts(color(:red, "    - #{format_rule(rule)}"))
    end

    for rule <- added do
      IO.puts(color(:green, "    + #{format_rule(rule)}"))
    end
  end

  defp normalize_sets(sets) do
    Enum.map(sets, fn
      {name, type} -> {name, type}
      {name, type, _opts} -> {name, type}
    end)
  end

  # --- Formatting helpers ---

  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  defp format_ip({a, b, c, d, e, f, g, h}) do
    [a, b, c, d, e, f, g, h]
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.join(":")
  end

  defp format_ip(ip) when is_binary(ip), do: ip
  defp format_ip(ip), do: inspect(ip)

  defp format_duration(seconds) when is_integer(seconds) do
    cond do
      seconds >= 86400 and rem(seconds, 86400) == 0 -> "#{div(seconds, 86400)}d"
      seconds >= 3600 and rem(seconds, 3600) == 0 -> "#{div(seconds, 3600)}h"
      seconds >= 60 and rem(seconds, 60) == 0 -> "#{div(seconds, 60)}m"
      true -> "#{seconds}s"
    end
  end

  defp format_duration(ms) when is_integer(ms), do: "#{ms}ms"

  defp kw(text), do: color(:dim, text)
  defp cnt(name), do: "#{color(:dim, "counter")} #{color(:yellow, to_string(name))}"

  defp verdict(:accept), do: color(:green, "accept")
  defp verdict(:drop), do: color(:red, "drop")
  defp verdict(:reject), do: color(:red, "reject")
end
