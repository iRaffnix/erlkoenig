defmodule Erlkoenig.Stack do
  @moduledoc """
  Unified DSL for the erlkoenig ecosystem.

  One file defines everything: host firewall, network zones, containers,
  BPF steering, threat detection, and counter monitoring.

      defmodule MyStack do
        use Erlkoenig.Stack

        images do ... end
        firewall "host" do ... end
        zone "apps" do ... end
        steering do ... end
        guard do ... end
        watch :metrics do ... end
      end

  Compile to an Erlang term file:

      erlkoenig compile stack.exs

  All blocks are optional. The compiled term is consumed by
  erlkoenig_config:load/1 at deploy time.
  """

  defmacro __using__(_opts) do
    quote do
      import Erlkoenig.Stack

      Module.register_attribute(__MODULE__, :stack_images, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_zones, accumulate: true)
      Module.register_attribute(__MODULE__, :stack_steering, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_firewall, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_guard, accumulate: false)
      Module.register_attribute(__MODULE__, :stack_watches, accumulate: true)

      Module.put_attribute(__MODULE__, :stack_images, Erlkoenig.Images.Builder.new())
      Module.put_attribute(__MODULE__, :stack_steering, nil)
      Module.put_attribute(__MODULE__, :stack_firewall, nil)
      Module.put_attribute(__MODULE__, :stack_guard, nil)

      @before_compile Erlkoenig.Stack
    end
  end

  defmacro __before_compile__(env) do
    images_b = Module.get_attribute(env.module, :stack_images)
    zones = Module.get_attribute(env.module, :stack_zones) |> Enum.reverse()
    steering_b = Module.get_attribute(env.module, :stack_steering)
    fw_config = Module.get_attribute(env.module, :stack_firewall)
    guard_config = Module.get_attribute(env.module, :stack_guard)
    watches = Module.get_attribute(env.module, :stack_watches) |> Enum.reverse()

    # Collect all container names across all zones
    all_names = Enum.flat_map(zones, fn z ->
      Enum.map(z.containers, & &1.name)
    end)

    # Check global uniqueness
    dupes = all_names -- Enum.uniq(all_names)
    if dupes != [] do
      raise CompileError,
        description: "duplicate container names across zones: #{inspect(Enum.uniq(dupes))}"
    end

    image_names = Erlkoenig.Images.Builder.image_names(images_b)

    # Validate zones
    Enum.each(zones, fn z ->
      Erlkoenig.Zone.Builder.validate!(z, image_names)
    end)

    # Validate steering
    if steering_b do
      Erlkoenig.Steering.Builder.validate!(steering_b, all_names)
    end

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

    # Auto-whitelist zone gateways in guard
    guard_with_gateways = if guard_config do
      gw_ips = Enum.map(zones, & &1.gateway) |> Enum.uniq()
      existing = Map.get(guard_config, :whitelist, [])
      new_wl = Enum.uniq(existing ++ gw_ips)
      Map.put(guard_config, :whitelist, new_wl)
    else
      guard_config
    end

    # Build term
    images_term = Erlkoenig.Images.Builder.to_term(images_b)
    zones_term = Enum.map(zones, &Erlkoenig.Zone.Builder.to_term(&1, images_b))
    steering_term = if steering_b, do: Erlkoenig.Steering.Builder.to_term(steering_b)

    term = %{}
    term = if images_term != %{}, do: Map.put(term, :images, images_term), else: term
    term = if fw_config, do: Map.put(term, :firewall, fw_config), else: term
    term = if zones_term != [], do: Map.put(term, :zones, zones_term), else: term
    term = if steering_term, do: Map.put(term, :steering, steering_term), else: term
    term = if guard_with_gateways, do: Map.put(term, :ct_guard, guard_with_gateways), else: term
    term = if watches != [], do: Map.put(term, :watch, hd(watches)), else: term

    quote do
      def config, do: unquote(Macro.escape(term))

      def write!(path) do
        formatted = :io_lib.format(~c"~tp.~n", [config()])
        File.write!(path, formatted)
      end
    end
  end

  # --- images block ---

  defmacro images(do: block) do
    quote do
      unquote(block)
    end
  end

  defmacro image(name, opts) do
    quote do
      @stack_images Erlkoenig.Images.Builder.add_image(
        @stack_images, unquote(name), unquote(opts))
    end
  end

  # --- firewall block (delegates to existing nft DSL) ---

  defmacro firewall(name, opts \\ [], do: block) do
    quote do
      # Use the existing ErlkoenigNft.Firewall.Builder
      var!(ek_fw_builder) = ErlkoenigNft.Firewall.Builder.new(
        unquote(name), unquote(opts))
      unquote(rewrite_firewall_block(block))
      @stack_firewall ErlkoenigNft.Firewall.Builder.to_term(var!(ek_fw_builder))
    end
  end

  # Rewrite firewall block macros to use var!(ek_fw_builder)
  # This delegates to the existing builder's functions
  defp rewrite_firewall_block(block), do: block

  # Firewall sub-macros (chain, set, counters, etc.)
  # These delegate to the ErlkoenigNft.Firewall module macros.
  # Users write them inside the firewall block.

  # We re-export the most common ones here so they work in Stack context.
  # The full set of firewall macros is available via `import ErlkoenigNft.Firewall`.

  # --- zone block ---

  defmacro zone(name, opts \\ [], do: block) do
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.new(
        unquote(name), unquote(opts))
      unquote(block)
      @stack_zones var!(ek_zone_builder)
    end
  end

  defmacro allow(target, opts \\ []) do
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.add_allow(
        var!(ek_zone_builder), unquote(target), unquote(opts))
    end
  end

  defmacro container(name, opts) do
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.begin_container(
        var!(ek_zone_builder), unquote(name), unquote(opts))
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.end_container(
        var!(ek_zone_builder))
    end
  end

  defmacro container(name, opts, do: block) do
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.begin_container(
        var!(ek_zone_builder), unquote(name), unquote(opts))
      unquote(block)
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.end_container(
        var!(ek_zone_builder))
    end
  end

  defmacro env(key, value) do
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.add_env(
        var!(ek_zone_builder), unquote(key), unquote(value))
    end
  end

  defmacro file(path, content) do
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.add_file(
        var!(ek_zone_builder), unquote(path), unquote(content))
    end
  end

  defmacro volume(container_path, opts) do
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.add_volume(
        var!(ek_zone_builder), unquote(container_path), unquote(opts))
    end
  end

  defmacro health_check(type, opts) do
    quote do
      var!(ek_zone_builder) = Erlkoenig.Zone.Builder.set_health_check(
        var!(ek_zone_builder), unquote(type), unquote(opts))
    end
  end

  # --- steering block ---

  defmacro steering(do: block) do
    quote do
      var!(ek_steering_builder) = Erlkoenig.Steering.Builder.new()
      unquote(block)
      @stack_steering var!(ek_steering_builder)
    end
  end

  defmacro service(name, opts) do
    quote do
      var!(ek_steering_builder) = Erlkoenig.Steering.Builder.add_service(
        var!(ek_steering_builder), unquote(name), unquote(opts))
    end
  end

  defmacro route(container_name) do
    quote do
      var!(ek_steering_builder) = Erlkoenig.Steering.Builder.add_route(
        var!(ek_steering_builder), unquote(container_name))
    end
  end

  # --- guard block (delegates to existing nft DSL) ---

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

  # --- watch block (delegates to existing nft DSL) ---

  defmacro watch(name, do: block) do
    quote do
      var!(ek_watch_builder) = ErlkoenigNft.Watch.Builder.new(unquote(name))
      unquote(block)
      @stack_watches ErlkoenigNft.Watch.Builder.to_term(var!(ek_watch_builder))
    end
  end
end
