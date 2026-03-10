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

defmodule Erlkoenig.Firewall do
  @moduledoc """
  DSL for defining Erlkoenig container firewall configurations.

  Compiles to Erlang terms compatible with `erlkoenig_firewall_nft`.

  ## Example

      defmodule MyFirewall do
        use Erlkoenig.Firewall

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

  alias Erlkoenig.Firewall.Builder

  defmacro __using__(_opts) do
    quote do
      import Erlkoenig.Firewall
      Module.register_attribute(__MODULE__, :fw_builder, accumulate: false)
    end
  end

  defmacro firewall(name, do: block) do
    quote do
      @fw_builder Builder.new(unquote(name))
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

  # --- Counters ---

  defmacro counters(names) do
    quote do
      @fw_builder Builder.add_counters(@fw_builder, unquote(names))
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
      @fw_builder Builder.push_rule(@fw_builder, Builder.tcp_accept(unquote(port), unquote(opts)))
    end
  end

  defmacro accept_udp(port) do
    quote do: @fw_builder Builder.push_rule(@fw_builder, Builder.udp_accept(unquote(port)))
  end

  defmacro accept_udp(port, opts) do
    quote do
      @fw_builder Builder.push_rule(@fw_builder, Builder.udp_accept(unquote(port), unquote(opts)))
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
end
