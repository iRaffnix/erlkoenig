defmodule Erlkoenig.Stack.HostMacros do
  @moduledoc false

  # ═══════════════════════════════════════════════════════════
  # host — the machine, its interfaces, IPVLAN zones, firewall
  # ═══════════════════════════════════════════════════════════

  @doc """
  Define the host machine — its interfaces, IPVLAN zones, and firewall tables.

  The `host` block is the top-level physical machine configuration.
  Everything inside describes what the host looks like *before* any
  containers are deployed: which network interfaces exist, which
  IPVLAN zones to create, and which nft tables to apply.

  There can be at most one `host` block per stack.

  ## Contains

  - `interface` — physical network interfaces
  - `ipvlan` — IPVLAN L3S zones (parent device + subnet — container
    slaves are placed directly into container netns)
  - `nft_table` — firewall tables (can also be outside `host`)

  ## Examples

      host do
        interface "eth0", zone: :wan
        interface "eth1", zone: :lan
        ipvlan "dmz",  parent: {:device, "eth0"},    subnet: {10, 0, 0, 0, 24}
        ipvlan "app",  parent: {:dummy,  "ek_app"},  subnet: {10, 0, 1, 0, 24}
        ipvlan "data", parent: {:dummy,  "ek_data"}, subnet: {10, 0, 2, 0, 24}
      end
  """
  defmacro host(do: block) do
    Module.register_attribute(__CALLER__.module, :__ek_context__, accumulate: false)
    Module.put_attribute(__CALLER__.module, :__ek_context__, :host)

    quote do
      var!(ek_host_builder) = Erlkoenig.Host.Builder.new()
      unquote(block)
      @stack_host var!(ek_host_builder)
    end
  end

  @doc """
  Declare a physical network interface on the host.

  Interfaces are informational — they tell the DSL which physical
  NICs exist and what zone they belong to. Zone labels are used in
  nft rules (e.g. `iifname: "eth0"`) and to pick IPVLAN parent devices.

  ## Options

  | Option | Type | Default | Description |
  |--------|------|---------|-------------|
  | `zone:` | atom | none | Zone classification: `:wan`, `:lan`, `:dmz`, etc. |

  ## Examples

      host do
        interface "eth0", zone: :wan    # internet-facing
        interface "eth1", zone: :lan    # internal network
        interface "lo"                  # loopback (no zone)
      end
  """
  defmacro interface(name, opts \\ []) do
    quote do
      var!(ek_host_builder) =
        Erlkoenig.Host.Builder.add_interface(
          var!(ek_host_builder),
          unquote(name),
          unquote(opts)
        )
    end
  end

  @doc """
  Declare an IPVLAN network segment on the host.

  Creates IPVLAN L3S slaves for containers. This is the only networking
  mode since ADR-0020.

  ## Options

    * `:parent` — (required) `{:device, "eth0"}` to attach to a physical
      host interface, or `{:dummy, "ek_<name>"}` to have erlkoenig create
      and own a kernel `dummy0` parent. Bare strings are rejected at
      compile time.
    * `:subnet` — (required) `{a, b, c, d, mask}` (only `/24` supported
      today) or `{a, b, c, d}` (defaults to `/24`).
    * `:mode` — `:l3s` (default), `:l3`, or `:l2`.
    * `:gateway` — optional gateway IP. Only meaningful for `{:dummy, ...}`
      parents (erlkoenig assigns it onto the dummy so containers can reach
      DNS etc. locally).

  ## Example

      host do
        interface "eth0"
        ipvlan "edge",  parent: {:device, "eth0"},    subnet: {10, 20, 0, 0, 24}
        ipvlan "inner", parent: {:dummy,  "ek_inner"}, subnet: {10, 40, 0, 0, 24}
      end
  """
  defmacro ipvlan(name, opts) do
    quote do
      var!(ek_host_builder) =
        Erlkoenig.Host.Builder.add_ipvlan(
          var!(ek_host_builder),
          unquote(name),
          unquote(opts)
        )
    end
  end
end
