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

  All rules use the generic `rule` macro:

      defmodule MyFirewall do
        use ErlkoenigNft.Firewall

        firewall "web" do
          counters [:ssh, :dropped]
          set "blocklist", :ipv4_addr, timeout: 3_600_000

          chain "inbound", hook: :input, policy: :drop do
            rule :accept, ct: :established
            rule :accept, iif: "lo"
            rule :accept, icmp: true
            rule :accept, tcp: 22, counter: :ssh, limit: {25, burst: 5}
            rule :accept, tcp: [80, 443]
            rule :drop, set: "blocklist", counter: :dropped
            rule :drop, log: "BLOCKED: "
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

  # --- Structural macros (sets, chains, counters) ---

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

  defmacro vmap(name, type, opts) do
    quote do
      @fw_builder Builder.add_vmap(@fw_builder, unquote(name), unquote(type), unquote(opts))
    end
  end

  defmacro counters(names) do
    quote do
      @fw_builder Builder.add_counters(@fw_builder, unquote(names))
    end
  end

  defmacro quota(name, bytes, opts \\ []) do
    quote do
      @fw_builder Builder.add_quota(@fw_builder, unquote(name), unquote(bytes), unquote(opts))
    end
  end

  defmacro flowtable(name, opts) do
    quote do
      @fw_builder Builder.add_flowtable(@fw_builder, unquote(name), unquote(opts))
    end
  end

  defmacro chain(name, opts, do: block) do
    quote do
      @fw_builder %{@fw_builder | rules_acc: []}
      unquote(block)
      {rules, builder} = Builder.take_rules(@fw_builder)
      @fw_builder Builder.add_chain(builder, unquote(name), unquote(opts), rules)
    end
  end

  # --- The one rule macro ---

  @doc """
  Generic rule builder. Every firewall rule uses this macro.

      rule :accept, tcp: 22, limit: {25, burst: 5}, counter: :ssh
      rule :accept, ct: :established
      rule :accept, iif: "lo"
      rule :accept, icmp: true
      rule :accept, tcp: 5432, saddr: {10, 0, 0, 0, 24}
      rule :drop, set: "blocklist", counter: :banned
      rule :drop, log: "DROP: ", counter: :dropped
      rule :masquerade, oif_neq: "eth0"

  Options:
    ct: :established         — conntrack state match
    icmp: true               — ICMP protocol match
    iif: "name"              — input interface (wildcard: "vh_*")
    oif: "name"              — output interface (wildcard ok)
    oif_neq: "name"          — output interface NOT equal
    tcp: port                — TCP destination port
    udp: port                — UDP destination port
    saddr: {a,b,c,d,prefix}  — source IP/subnet
    daddr: {a,b,c,d,prefix}  — destination IP/subnet
    set: "name"              — match source IP against named set
    log: "prefix"            — log with prefix
    limit: {rate, burst: n}  — rate limit
    counter: :name           — named counter
  """
  defmacro rule(verdict, opts \\ []) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder,
        Builder.build_rule(unquote(verdict), unquote(opts)))
    end
  end
end
