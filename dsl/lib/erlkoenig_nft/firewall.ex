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

defmodule ErlkoenigNft.Firewall do
  @moduledoc """
  DSL for defining nf_tables firewall configurations.

  Compiles to Erlang terms compatible with `erlkoenig_nft`.

  ## Example

      defmodule MyFirewall do
        use ErlkoenigNft.Firewall

        firewall "web" do
          counters [:ssh, :dropped]
          set "blocklist", :ipv4_addr, timeout: 3600

          chain "inbound", hook: :input, policy: :drop do
            accept :established
            accept :icmp
            accept_tcp 22, counter: :ssh, limit: {5, burst: 2}
            accept_tcp [80, 443]
            drop_if_in_set "blocklist", counter: :dropped
            log_and_drop "BLOCKED: "
          end
        end
      end

      MyFirewall.config()   # => Erlang term map
  """

  alias ErlkoenigNft.Firewall.Builder

  defmacro __using__(_opts) do
    quote do
      import ErlkoenigNft.Firewall
      Module.register_attribute(__MODULE__, :fw_builder, accumulate: false)
    end
  end

  defmacro firewall(name, opts \\ [], do: block) do
    quote do
      @fw_builder Builder.new(unquote(name), unquote(opts))
      unquote(block)

      def config do
        Builder.to_term(@fw_builder)
      end

      def write!(path) do
        Builder.write!(@fw_builder, path)
      end
    end
  end

  # --- Sets ---

  defmacro set(name, type) do
    quote do
      @fw_builder Builder.add_set(@fw_builder, unquote(name), unquote(type))
    end
  end

  defmacro set(name, type, opts) do
    quote do
      @fw_builder Builder.add_set(@fw_builder, unquote(name), unquote(type), unquote(opts))
    end
  end

  # --- Concatenated Sets ---

  defmacro concat_set(name, fields) do
    quote do
      @fw_builder Builder.add_concat_set(@fw_builder, unquote(name), unquote(fields))
    end
  end

  defmacro concat_set(name, fields, opts) do
    quote do
      @fw_builder Builder.add_concat_set(@fw_builder, unquote(name), unquote(fields), unquote(opts))
    end
  end

  # --- Verdict Maps ---

  defmacro vmap(name, type, opts) do
    quote do
      @fw_builder Builder.add_vmap(@fw_builder, unquote(name), unquote(type), unquote(opts))
    end
  end

  # --- Counters ---

  defmacro counters(names) do
    quote do
      @fw_builder Builder.add_counters(@fw_builder, unquote(names))
    end
  end

  # --- Quotas ---

  defmacro quota(name, bytes, opts \\ []) do
    quote do
      @fw_builder Builder.add_quota(@fw_builder, unquote(name), unquote(bytes), unquote(opts))
    end
  end

  # --- Chain ---

  defmacro chain(name, opts, do: block) do
    quote do
      @fw_builder %{@fw_builder | rules_acc: []}
      unquote(block)
      {rules, builder} = Builder.take_rules(@fw_builder)
      @fw_builder Builder.add_chain(builder, unquote(name), unquote(opts), rules)
    end
  end

  # --- Rule macros ---

  defmacro accept(:established) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.ct_established_accept())
  end

  defmacro accept(:icmp) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.icmp_accept())
  end

  defmacro accept(:loopback) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.iifname_accept("lo"))
  end

  defmacro accept(:all) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.accept())
  end

  defmacro accept_tcp(ports) when is_list(ports) do
    rules =
      Enum.map(ports, fn port ->
        quote do: Builder.tcp_accept(unquote(port))
      end)

    quote do
      Enum.each(unquote(rules), fn rule ->
        @fw_builder Builder.push_rule(@fw_builder, rule)
      end)
    end
  end

  defmacro accept_tcp(port) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.tcp_accept(unquote(port)))
  end

  defmacro accept_tcp(port, opts) do
    quote do
      @fw_builder Builder.push_rule_with_counter(@fw_builder,
        Builder.tcp_accept(unquote(port), unquote(opts)))
    end
  end

  defmacro accept_udp(port) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.udp_accept(unquote(port)))
  end

  defmacro accept_udp(port, opts) do
    quote do
      @fw_builder Builder.push_rule_with_counter(@fw_builder,
        Builder.udp_accept(unquote(port), unquote(opts)))
    end
  end

  defmacro accept_tcp_range(from, to_port) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.tcp_port_range_accept(unquote(from), unquote(to_port)))
    end
  end

  defmacro accept_udp_range(from, to_port) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.udp_port_range_accept(unquote(from), unquote(to_port)))
    end
  end

  defmacro reject_tcp(port) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.tcp_reject(unquote(port)))
  end

  defmacro accept_protocol(proto) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.protocol_accept(unquote(proto)))
  end

  defmacro accept_from(ip) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.ip_saddr_accept(unquote(ip)))
  end

  defmacro drop_from(ip) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.ip_saddr_drop(unquote(ip)))
  end

  defmacro drop_if_in_set(set_name) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.set_lookup_drop(unquote(set_name)))
  end

  defmacro drop_if_in_set(set_name, opts) do
    quote do
      counter = Keyword.get(unquote(opts), :counter)

      rule =
        if counter,
          do: Builder.set_lookup_drop(unquote(set_name), counter),
          else: Builder.set_lookup_drop(unquote(set_name))

      @fw_builder Builder.push_rule(@fw_builder, rule)
    end
  end

  defmacro connlimit_drop(max) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.connlimit_drop(unquote(max)))
  end

  defmacro connlimit_drop(max, offset) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.connlimit_drop(unquote(max), unquote(offset)))
    end
  end

  defmacro log_and_drop(prefix) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.log_drop(unquote(prefix)))
  end

  defmacro log_and_drop(prefix, opts) do
    quote do
      counter = Keyword.get(unquote(opts), :counter)

      rule =
        if counter,
          do: Builder.log_drop(unquote(prefix), counter),
          else: Builder.log_drop(unquote(prefix))

      @fw_builder Builder.push_rule(@fw_builder, rule)
    end
  end

  defmacro log_and_reject(prefix) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.log_reject(unquote(prefix)))
  end

  # --- Interface matching ---

  defmacro accept_on_interface(name) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.iifname_accept(unquote(name)))
  end

  defmacro accept_output_interface(name) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.oifname_accept(unquote(name)))
  end

  defmacro masquerade do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.masquerade())
  end

  defmacro masquerade_not_via(name) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.oifname_neq_masq(unquote(name)))
  end

  defmacro accept_forward_established do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.forward_established())
  end

  # --- NAT: DNAT ---

  @doc "DNAT: redirect incoming TCP traffic on match_port to dst_ip:dst_port"
  defmacro dnat(match_port, dst_ip, dst_port) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder,
        Builder.tcp_dnat(unquote(match_port), unquote(dst_ip), unquote(dst_port)))
    end
  end

  @doc "SNAT: rewrite source address to ip:port (static source NAT)"
  defmacro snat(ip, port) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder,
        Builder.snat(unquote(ip), unquote(port)))
    end
  end

  # --- Zone definitions ---

  defmacro zone(name, opts) do
    quote do
      @fw_builder Builder.add_zone(@fw_builder, unquote(name), unquote(opts))
    end
  end

  defmacro zone_input(zone_name, opts, do: block) do
    quote do
      @fw_builder %{@fw_builder | rules_acc: []}
      unquote(block)
      {rules, builder} = Builder.take_rules(@fw_builder)
      @fw_builder Builder.add_zone_input(builder, unquote(zone_name),
        Keyword.get(unquote(opts), :policy, :drop), rules)
    end
  end

  defmacro zone_forward(from_zone, opts, do: block) do
    quote do
      @fw_builder %{@fw_builder | rules_acc: []}
      unquote(block)
      {rules, builder} = Builder.take_rules(@fw_builder)
      to_zone = Keyword.fetch!(unquote(opts), :to)
      policy = Keyword.get(unquote(opts), :policy, :drop)
      @fw_builder Builder.add_zone_forward(builder, unquote(from_zone), to_zone, policy, rules)
    end
  end

  defmacro zone_masquerade(from_zone, opts) do
    quote do
      to_zone = Keyword.fetch!(unquote(opts), :to)
      @fw_builder Builder.add_zone_masquerade(@fw_builder, unquote(from_zone), to_zone)
    end
  end

  # --- SYN proxy ---

  defmacro synproxy(ports, opts) do
    quote do
      ports = unquote(ports)
      opts = unquote(opts)
      port_list = if is_list(ports), do: ports, else: [ports]

      Enum.each(port_list, fn port ->
        @fw_builder Builder.push_rule(
          @fw_builder,
          Builder.synproxy_filter(port, opts)
        )
      end)
    end
  end

  # --- Notrack ---

  defmacro notrack(port, proto) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.notrack_rule(unquote(port), unquote(proto)))
    end
  end

  # --- Meter macros ---

  defmacro meter_limit(name, port, proto, opts) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder,
        Builder.meter_limit(unquote(name), unquote(port), unquote(proto), unquote(opts)))
    end
  end

  # --- NFQUEUE macros ---

  defmacro queue_to(port, proto, opts) do
    quote do
      @fw_builder Builder.push_rule(
        @fw_builder,
        Builder.queue_rule(unquote(port), unquote(proto), unquote(opts))
      )
    end
  end

  # --- Verdict map dispatch ---

  defmacro dispatch(proto, vmap_name) do
    quote do
      @fw_builder Builder.push_rule(
        @fw_builder,
        Builder.vmap_dispatch(unquote(proto), unquote(vmap_name))
      )
    end
  end

  # --- Concatenated set matching ---

  defmacro accept_if_in_concat_set(set_name, fields) do
    quote do
      @fw_builder Builder.push_rule(
        @fw_builder,
        Builder.accept_if_in_concat_set(unquote(set_name), unquote(fields))
      )
    end
  end

  # --- Cgroup matching ---

  defmacro match_cgroup(cgroup_id, :accept) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.cgroup_accept(unquote(cgroup_id)))
    end
  end

  defmacro match_cgroup(cgroup_id, :drop) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.cgroup_drop(unquote(cgroup_id)))
    end
  end

  # --- Flowtable macros ---

  defmacro flowtable(name, opts) do
    quote do
      @fw_builder Builder.add_flowtable(@fw_builder, unquote(name), unquote(opts))
    end
  end

  defmacro offload(flowtable_name) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.flow_offload(unquote(flowtable_name)))
    end
  end

  # --- ct mark macros ---

  defmacro mark_connection(value) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.ct_mark_set(unquote(value)))
    end
  end

  defmacro match_mark(value, opts) do
    quote do
      verdict = Keyword.get(unquote(opts), :verdict, :accept)
      @fw_builder Builder.push_rule(@fw_builder, Builder.ct_mark_match(unquote(value), verdict))
    end
  end

  # --- FIB / RPF macros ---

  defmacro rpf_check do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.fib_rpf_drop())
  end

  # --- OS Fingerprinting ---

  defmacro match_os(os_name, verdict) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.osf_match(unquote(os_name), unquote(verdict)))
    end
  end

  defmacro drop_if_in_concat_set(set_name, fields) do
    quote do
      @fw_builder Builder.push_rule(
        @fw_builder,
        Builder.drop_if_in_concat_set(unquote(set_name), unquote(fields))
      )
    end
  end

  # --- NFLOG macros ---

  defmacro accept_udp_if_in_set(set_name, port) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.set_lookup_udp_accept(unquote(set_name), unquote(port)))
    end
  end

  defmacro log_and_drop_nflog(prefix, opts) do
    quote do
      group = Keyword.get(unquote(opts), :group, 0)
      counter = Keyword.get(unquote(opts), :counter)

      rule =
        if counter,
          do: Builder.log_drop_nflog(unquote(prefix), group, counter),
          else: Builder.log_drop_nflog(unquote(prefix), group, "unknown")

      @fw_builder Builder.push_rule(@fw_builder, rule)
    end
  end
end
