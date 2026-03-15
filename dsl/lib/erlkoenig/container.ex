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

defmodule Erlkoenig.Container do
  @moduledoc """
  DSL macros for defining Erlkoenig containers.

  ## Example

      defmodule MyContainers do
        use Erlkoenig.Container

        defaults do
          firewall :standard
        end

        container :web_api do
          binary "/opt/bin/api_server"
          ip {10, 0, 0, 10}
          ports [{8080, 80}, {8443, 443}]
          env %{"PORT" => "80"}
          firewall :strict, allow_tcp: [80, 443]
        end

        container :worker do
          binary "/opt/bin/worker"
          ip {10, 0, 0, 20}
          args ["--threads", "4"]
        end
      end

      MyContainers.containers()        # => list of term maps
      MyContainers.container(:web_api)  # => single term map
  """

  alias Erlkoenig.Container.Builder

  defmacro __using__(_opts) do
    quote do
      import Erlkoenig.Container
      Module.register_attribute(__MODULE__, :ct_builders, accumulate: true)
      Module.register_attribute(__MODULE__, :ct_current, accumulate: false)
      Module.register_attribute(__MODULE__, :ct_defaults, accumulate: false)
      Module.register_attribute(__MODULE__, :ct_guard_acc, accumulate: false)
      @ct_defaults %{}
      @ct_guard_acc %{}

      @before_compile Erlkoenig.Container
    end
  end

  defmacro __before_compile__(_env) do
    quote do
      def containers do
        @ct_builders
        |> Enum.reverse()
        |> Enum.map(fn builder ->
          Builder.to_term(builder)
        end)
      end

      def spawn_opts do
        @ct_builders
        |> Enum.reverse()
        |> Enum.map(fn builder ->
          {builder.name, builder.binary, Builder.to_spawn_opts(builder)}
        end)
      end

      def write!(path) do
        terms = containers()
        config = %{containers: terms, defaults: @ct_defaults}
        formatted = :io_lib.format(~c"~tp.~n", [config])
        File.write!(path, formatted)
      end
    end
  end

  # --- Defaults ---

  defmacro defaults(do: block) do
    quote do
      @ct_defaults %{}
      unquote(block)
    end
  end

  # --- Container definition ---

  defmacro container(name, do: block) do
    quote do
      @ct_current Builder.new(unquote(name))
      unquote(block)
      @ct_builders @ct_current
    end
  end

  # --- Container properties ---

  defmacro binary(path) do
    quote do: @ct_current Builder.set_binary(@ct_current, unquote(path))
  end

  defmacro signature(mode_or_path) do
    quote do: @ct_current Builder.set_signature(@ct_current, unquote(mode_or_path))
  end

  defmacro ip(addr) do
    quote do: @ct_current Builder.set_ip(@ct_current, unquote(addr))
  end

  defmacro ports(port_list) do
    quote do: @ct_current Builder.set_ports(@ct_current, unquote(port_list))
  end

  defmacro args(arg_list) do
    quote do: @ct_current Builder.set_args(@ct_current, unquote(arg_list))
  end

  defmacro env(env_map) do
    quote do: @ct_current Builder.set_env(@ct_current, unquote(env_map))
  end

  # --- Firewall (inline nftables rules) ---

  defmacro firewall(do: block) do
    quote do
      unquote(block)
    end
  end

  # Firewall rules
  defmacro accept(:established) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, :ct_established_accept)
  end
  defmacro accept(:loopback) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, {:iifname_accept, "lo"})
  end
  defmacro accept(:icmp) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, :icmp_accept)
  end
  defmacro accept(:all) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, :accept)
  end

  defmacro accept_tcp(port) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, {:tcp_accept, unquote(port)})
  end
  defmacro accept_tcp(port, opts) do
    quote do
      rule = case unquote(opts) do
        [counter: c] ->
          {:tcp_accept, unquote(port), to_string(c)}
        [counter: c, limit: {rate, burst: b}] ->
          {:tcp_accept_limited, unquote(port), to_string(c), %{rate: rate, burst: b}}
        [limit: {rate, burst: b}] ->
          {:tcp_accept_limited, unquote(port), "limited", %{rate: rate, burst: b}}
        _ ->
          {:tcp_accept, unquote(port)}
      end
      @ct_current Builder.add_fw_rule(@ct_current, rule)
    end
  end

  defmacro accept_udp(port) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, {:udp_accept, unquote(port)})
  end

  defmacro accept_from(ip) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, {:ip_saddr_accept, unquote(ip)})
  end

  defmacro accept_protocol(proto) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, {:protocol_accept, unquote(proto)})
  end

  defmacro connlimit_drop(max) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, {:connlimit_drop, unquote(max), 0})
  end

  defmacro drop_if_in_set(set_name) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, {:set_lookup_drop, unquote(set_name)})
  end
  defmacro drop_if_in_set(set_name, opts) do
    quote do
      rule = case unquote(opts) do
        [counter: c] -> {:set_lookup_drop, unquote(set_name), to_string(c)}
        _ -> {:set_lookup_drop, unquote(set_name)}
      end
      @ct_current Builder.add_fw_rule(@ct_current, rule)
    end
  end

  defmacro log_and_drop(prefix) do
    quote do: @ct_current Builder.add_fw_rule(@ct_current, {:log_drop, unquote(prefix)})
  end
  defmacro log_and_drop(prefix, opts) do
    quote do
      rule = case unquote(opts) do
        [counter: c] -> {:log_drop, unquote(prefix), to_string(c)}
        _ -> {:log_drop, unquote(prefix)}
      end
      @ct_current Builder.add_fw_rule(@ct_current, rule)
    end
  end

  defmacro counters(names) do
    quote do: @ct_current Builder.set_fw_counters(@ct_current, unquote(names))
  end

  defmacro set(name, type) do
    quote do: @ct_current Builder.add_fw_set(@ct_current, unquote(name), unquote(type))
  end

  # --- Guard (threat detection) ---

  defmacro guard(do: block) do
    quote do
      @ct_guard_acc %{}
      unquote(block)
      @ct_current Builder.set_guard(@ct_current, @ct_guard_acc)
    end
  end

  defmacro detect(type, opts) do
    quote do
      threshold = Keyword.fetch!(unquote(opts), :threshold)
      window = Keyword.fetch!(unquote(opts), :window)
      @ct_guard_acc Map.put(@ct_guard_acc, unquote(type), {threshold, window})
    end
  end

  defmacro ban_duration(seconds) do
    quote do: @ct_guard_acc Map.put(@ct_guard_acc, :ban_duration, unquote(seconds))
  end

  # --- Restart ---

  defmacro restart(policy) do
    quote do: @ct_current Builder.set_restart(@ct_current, unquote(policy))
  end

  # --- Files ---

  defmacro files(file_map) do
    quote do: @ct_current Builder.set_files(@ct_current, unquote(file_map))
  end

  defmacro file(path, content) do
    quote do: @ct_current Builder.add_file(@ct_current, unquote(path), unquote(content))
  end

  # --- DNS Name ---

  defmacro dns_name(name) do
    quote do: @ct_current Builder.set_dns_name(@ct_current, unquote(name))
  end

  # --- Limits ---

  defmacro limits(opts) do
    quote do
      limits_term = Erlkoenig.Limits.build(unquote(opts))
      @ct_current Builder.set_limits(@ct_current, limits_term)
    end
  end

  # --- Health Check ---

  defmacro health_check(opts) do
    quote do
      @ct_current Builder.set_health_check(@ct_current, unquote(opts))
    end
  end

  # --- Zone ---

  defmacro zone(name) when is_atom(name) do
    quote do: @ct_current Builder.set_zone(@ct_current, unquote(name))
  end

  # --- Capabilities ---

  defmacro caps(cap_list) do
    quote do: @ct_current Builder.set_caps(@ct_current, unquote(cap_list))
  end

  # --- Seccomp ---

  defmacro seccomp(profile) when is_atom(profile) do
    quote do
      seccomp_term = Erlkoenig.Seccomp.get(unquote(profile))
      @ct_current %{@ct_current | seccomp: seccomp_term}
    end
  end
end
