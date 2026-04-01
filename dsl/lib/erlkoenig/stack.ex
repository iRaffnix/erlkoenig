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

defmodule Erlkoenig.Stack do
  @moduledoc """
  Unified DSL for the erlkoenig ecosystem.

  One file defines everything: host firewall, pods, zones,
  BPF steering, threat detection, and counter monitoring.

  ## Architecture Principle

  Four subsystems, cleanly separated:

    1. `firewall` / zone `chain`/`rule` — nft kernel objects
    2. `pod` / `deploy` — compiler expansion (template)
    3. `guard` / `watch` — Erlang runtime processes
    4. `steer` — eBPF map state (erlkoenig_ebpfd)

  ## Syntax

      defmodule MyInfra do
        use Erlkoenig.Stack

        firewall "host" do ... end
        pod "webstack" do ... end
        zone "production" do ... end
        guard do ... end
        watch :metrics do ... end
      end

  ## References

  `@name` inside pod/zone `iif:`/`oif:` is a compile-time reference
  to a container name. Resolved to veth names at deploy time.
  `"string"` is a raw nft interface name, passed 1:1 to the kernel.
  """

  defmacro __using__(_opts) do
    quote do
      import Erlkoenig.Stack

      Module.register_attribute(__MODULE__, :stack_pods, accumulate: true)
      Module.register_attribute(__MODULE__, :stack_zones, accumulate: true)
      Module.register_attribute(__MODULE__, :stack_firewall, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_guard, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_watches, accumulate: true)

      Module.put_attribute(__MODULE__, :stack_firewall, nil)
      Module.put_attribute(__MODULE__, :stack_guard, nil)

      @before_compile Erlkoenig.Stack
    end
  end

  defmacro __before_compile__(env) do
    pods = Module.get_attribute(env.module, :stack_pods) |> Enum.reverse()
    zones = Module.get_attribute(env.module, :stack_zones) |> Enum.reverse()
    fw_config = Module.get_attribute(env.module, :stack_firewall)
    guard_config = Module.get_attribute(env.module, :stack_guard)
    watches = Module.get_attribute(env.module, :stack_watches) |> Enum.reverse()

    # Validate pods
    Enum.each(pods, &Erlkoenig.Pod.Builder.validate!/1)

    # Validate pod name uniqueness
    pod_names = Enum.map(pods, & &1.name)
    dupes = pod_names -- Enum.uniq(pod_names)
    if dupes != [] do
      raise CompileError,
        description: "duplicate pod names: #{inspect(Enum.uniq(dupes))}"
    end

    # Validate zones reference existing pods
    Enum.each(zones, fn zone ->
      Enum.each(zone.deployments, fn {pod_name, _replicas} ->
        unless pod_name in pod_names do
          raise CompileError,
            description: "zone #{inspect(zone.name)}: deploy references unknown pod #{inspect(pod_name)}. " <>
              "Known pods: #{inspect(pod_names)}"
        end
      end)
    end)

    # Validate watch counters against firewall counters
    if fw_config && watches != [] do
      fw_counters = Map.get(fw_config, :counters, []) |> Enum.map(&to_string/1)
      Enum.each(watches, fn w ->
        Enum.each(Map.get(w, :counters, []), fn c ->
          cname = to_string(c)
          if cname not in fw_counters do
            raise CompileError,
              description: "watch references undeclared counter #{inspect(c)}. " <>
                "Declare it in the firewall counters list."
          end
        end)
      end)
    end

    # Build term
    pods_term = Enum.map(pods, &Erlkoenig.Pod.Builder.to_term/1)
    zones_term = Enum.map(zones, &Erlkoenig.Zone.Builder.to_term/1)

    term = %{}
    term = if fw_config, do: Map.put(term, :firewall, fw_config), else: term
    term = if pods_term != [], do: Map.put(term, :pods, pods_term), else: term
    term = if zones_term != [], do: Map.put(term, :zones, zones_term), else: term
    term = if guard_config, do: Map.put(term, :ct_guard, guard_config), else: term
    term = if watches != [], do: Map.put(term, :watch, hd(watches)), else: term

    quote do
      def config, do: unquote(Macro.escape(term))

      def write!(path) do
        formatted = :io_lib.format(~c"~tp.~n", [config()])
        File.write!(path, formatted)
      end
    end
  end

  # ═══════════════════════════════════════════════════════════
  # firewall block — delegates to ErlkoenigNft.Firewall
  # ═══════════════════════════════════════════════════════════

  defmacro firewall(name, opts \\ [], do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :firewall)

    quote do
      Module.register_attribute(__MODULE__, :fw_builder, accumulate: false)
      @fw_builder ErlkoenigNft.Firewall.Builder.new(unquote(name), unquote(opts))
      unquote(block)
      @stack_firewall ErlkoenigNft.Firewall.Builder.to_term(@fw_builder)
    end
  end

  # ═══════════════════════════════════════════════════════════
  # pod block — template definition
  # ═══════════════════════════════════════════════════════════

  defmacro pod(name, do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :pod)

    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.new(unquote(name))
      unquote(block)
      @stack_pods var!(ek_pod_builder)
    end
  end

  # container inside pod — always dispatched from pod context
  # The pod macro sets var!(ek_pod_builder), so container is always
  # called from within a pod or zone block.

  defmacro container(name, opts) when is_list(opts) do
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_container(
        var!(ek_pod_builder), unquote(to_string(name)), unquote(opts))
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_container(
        var!(ek_pod_builder))
    end
  end

  defmacro container(name, opts, do: block) when is_list(opts) do
    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_container(
        var!(ek_pod_builder), unquote(to_string(name)), unquote(opts))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_container(
        var!(ek_pod_builder))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # chain / rule — same syntax everywhere
  # ═══════════════════════════════════════════════════════════

  # chain and rule dispatch at macro-expansion time using the caller's
  # __ek_context__ module attribute. This avoids expanding var!(ek_pod_builder)
  # in a firewall context (which would cause undefined variable errors).

  @doc """
  Define a chain. Works in firewall, pod, container, and zone contexts.
  Same syntax everywhere.
  """
  defmacro chain(name, opts \\ [], do: block) do
    ctx = Module.get_attribute(__CALLER__.module, :__ek_context__)
    case ctx do
      :firewall ->
        quote do
          @fw_builder %{@fw_builder | rules_acc: []}
          unquote(block)
          {rules, builder} = ErlkoenigNft.Firewall.Builder.take_rules(@fw_builder)
          @fw_builder ErlkoenigNft.Firewall.Builder.add_chain(
            builder, unquote(name), unquote(opts), rules)
        end

      :pod ->
        quote do
          var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_chain(
            var!(ek_pod_builder), unquote(name), unquote(opts))
          unquote(block)
          var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_chain(
            var!(ek_pod_builder), unquote(name), unquote(opts))
        end

      :zone ->
        quote do
          var!(ek_zone_builder) = Erlkoenig.Zone.Builder.begin_chain(
            var!(ek_zone_builder), unquote(name), unquote(opts))
          unquote(block)
          var!(ek_zone_builder) = Erlkoenig.Zone.Builder.end_chain(
            var!(ek_zone_builder), unquote(name), unquote(opts))
        end
    end
  end

  @doc """
  Define a rule. Same syntax in all contexts.
  """
  defmacro rule(verdict, opts \\ []) do
    ctx = Module.get_attribute(__CALLER__.module, :__ek_context__)
    case ctx do
      :firewall ->
        quote do
          @fw_builder ErlkoenigNft.Firewall.Builder.push_rule(
            @fw_builder,
            ErlkoenigNft.Firewall.Builder.build_rule(unquote(verdict), unquote(opts)))
        end

      :pod ->
        quote do
          rule_term = ErlkoenigNft.Firewall.Builder.build_rule(
            unquote(verdict), unquote(opts))
          pod = var!(ek_pod_builder)
          var!(ek_pod_builder) = if pod.current_ct != nil do
            Erlkoenig.Pod.Builder.push_rule_to_ct(pod, rule_term)
          else
            Erlkoenig.Pod.Builder.push_rule_to_pod(pod, rule_term)
          end
        end

      :zone ->
        quote do
          var!(ek_zone_builder) = Erlkoenig.Zone.Builder.push_rule(
            var!(ek_zone_builder),
            ErlkoenigNft.Firewall.Builder.build_rule(unquote(verdict), unquote(opts)))
        end
    end
  end

  # ═══════════════════════════════════════════════════════════
  # zone block
  # ═══════════════════════════════════════════════════════════

  defmacro zone(name, opts \\ [], do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :zone)

    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.new(
        unquote(name), unquote(opts))
      unquote(block)
      @stack_zones var!(ek_zone_builder)
    end
  end

  defmacro deploy(pod_name, opts) do
    replicas = Keyword.fetch!(opts, :replicas)
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.add_deployment(
        var!(ek_zone_builder), unquote(pod_name), unquote(replicas))
    end
  end

  defmacro steer(vip, opts) do
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.add_steer(
        var!(ek_zone_builder), unquote(vip), unquote(opts))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # nft object declarations (work in firewall and zone)
  # ═══════════════════════════════════════════════════════════

  defmacro set(name, type) do
    quote do
      @fw_builder ErlkoenigNft.Firewall.Builder.add_set(@fw_builder, unquote(name), unquote(type))
    end
  end

  defmacro set(name, type, opts) do
    quote do
      @fw_builder ErlkoenigNft.Firewall.Builder.add_set(@fw_builder, unquote(name), unquote(type), unquote(opts))
    end
  end

  defmacro counters(names) do
    quote do
      @fw_builder ErlkoenigNft.Firewall.Builder.add_counters(@fw_builder, unquote(names))
    end
  end

  defmacro vmap(name, type, opts) do
    quote do
      @fw_builder ErlkoenigNft.Firewall.Builder.add_vmap(@fw_builder, unquote(name), unquote(type), unquote(opts))
    end
  end

  defmacro flowtable(name, opts) do
    quote do
      @fw_builder ErlkoenigNft.Firewall.Builder.add_flowtable(@fw_builder, unquote(name), unquote(opts))
    end
  end

  defmacro quota(name, opts) do
    bytes = Keyword.fetch!(opts, :bytes)
    quote do
      @fw_builder ErlkoenigNft.Firewall.Builder.add_quota(@fw_builder, unquote(name), unquote(bytes), unquote(opts))
    end
  end

  defmacro meter(name, opts) do
    quote do
      @fw_builder ErlkoenigNft.Firewall.Builder.add_meter(@fw_builder, unquote(name), unquote(opts))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # guard block — Erlang runtime (erlkoenig_nft_ct_guard)
  # ═══════════════════════════════════════════════════════════

  defmacro guard(do: block) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.new()
      unquote(block)
      @stack_guard ErlkoenigNft.Guard.Builder.to_term(var!(ek_guard_builder))
    end
  end

  defmacro detect(type, opts) do
    threshold = Keyword.fetch!(opts, :threshold)
    window = Keyword.fetch!(opts, :window)
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.add_detector(
        var!(ek_guard_builder), unquote(type), unquote(threshold), unquote(window))
    end
  end

  defmacro ban_duration(seconds) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_ban_duration(
        var!(ek_guard_builder), unquote(seconds))
    end
  end

  defmacro whitelist(ip) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.add_whitelist(
        var!(ek_guard_builder), unquote(ip))
    end
  end

  defmacro watch_set(set_name) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.set_target(
        var!(ek_guard_builder), unquote(set_name))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # watch block — Erlang runtime (erlkoenig_nft_watch)
  # ═══════════════════════════════════════════════════════════

  defmacro watch(name, do: block) do
    quote do
      var!(ek_watch_builder) = ErlkoenigNft.Watch.Builder.new(unquote(name))
      unquote(block)
      @stack_watches ErlkoenigNft.Watch.Builder.to_term(var!(ek_watch_builder))
    end
  end
end
