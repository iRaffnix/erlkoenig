defmodule Erlkoenig.Zone.Builder do
  @moduledoc """
  Accumulates zone definitions with their containers.

  A zone groups containers that share a network segment (bridge, subnet,
  IP pool, gateway). Network access is deny-by-default — every allowed
  path must be declared explicitly via `allow`.

  ## Network Policy

  Without `allow` directives, the zone is fully isolated. No traffic
  leaves the bridge — not even DNS, not even to the host.

      allow :dns                        # container → bridge DNS (port 53)
      allow :gateway, ports: [5432]     # container → host service
      allow :gateway                    # container → host, all ports
      allow :internet, via: "eth0"      # container → internet (masquerade)
      allow :zone, "other_zone"         # container → other zone's bridge

  ## IP Pool

  The pool defines which IPs are auto-allocated to containers.
  Gateway and other infrastructure IPs stay outside the pool.

      zone "apps",
        subnet: {10, 0, 0, 0},
        pool: {10, 0, 0, 10}..{10, 0, 0, 250} do
  """

  defstruct name: nil,
            subnet: {10, 0, 0, 0},
            gateway: nil,
            netmask: 24,
            bridge: nil,
            pool_start: nil,
            pool_end: nil,
            interface: nil,
            allows: [],
            containers: [],
            current_ct: nil

  def new(name, opts) do
    subnet = Keyword.get(opts, :subnet, {10, 0, 0, 0})
    {sa, sb, sc, _} = subnet

    {pool_start, pool_end} = case Keyword.get(opts, :pool) do
      {first, last} when is_tuple(first) and is_tuple(last) -> {first, last}
      nil -> {{sa, sb, sc, 2}, {sa, sb, sc, 254}}
    end

    %__MODULE__{
      name: to_string(name),
      subnet: subnet,
      gateway: Keyword.get(opts, :gateway, {sa, sb, sc, 1}),
      netmask: Keyword.get(opts, :netmask, 24),
      bridge: Keyword.get(opts, :bridge) && to_string(Keyword.get(opts, :bridge))
              || "ek_br_#{name}",
      pool_start: pool_start,
      pool_end: pool_end,
      interface: Keyword.get(opts, :interface) && to_string(Keyword.get(opts, :interface))
    }
  end

  # --- Network policy (allow directives) ---

  def add_allow(%__MODULE__{allows: allows} = z, :dns, _opts) do
    %{z | allows: allows ++ [:dns]}
  end

  def add_allow(%__MODULE__{allows: allows} = z, :gateway, opts) do
    entry = case Keyword.get(opts, :ports) do
      nil -> :gateway
      ports when is_list(ports) -> {:gateway, ports}
    end
    %{z | allows: allows ++ [entry]}
  end

  def add_allow(%__MODULE__{allows: allows} = z, :internet, opts) do
    via = Keyword.fetch!(opts, :via)
    %{z | allows: allows ++ [{:internet, to_string(via)}]}
  end

  def add_allow(%__MODULE__{allows: allows} = z, :zone, opts) do
    target = case opts do
      [name] when is_binary(name) -> {:zone, name}
      [{:name, name}] -> {:zone, to_string(name)}
      name when is_binary(name) -> {:zone, name}
    end
    %{z | allows: allows ++ [target]}
  end

  # --- Container lifecycle ---

  def begin_container(%__MODULE__{} = z, name, opts) do
    ct = %{
      name: to_string(name),
      image: opts[:image] && to_string(opts[:image]),
      binary: opts[:binary] && to_string(opts[:binary]),
      ip: opts[:ip],
      ports: opts[:ports] || [],
      limits: opts[:limits] || %{},
      restart: opts[:restart] || :no_restart,
      seccomp: opts[:seccomp] || :default,
      uid: opts[:uid] || 65534,
      gid: opts[:gid] || 65534,
      args: opts[:args] || [],
      caps: opts[:caps] || [],
      env: [],
      files: %{},
      volumes: [],
      health_check: nil,
      firewall: nil
    }
    %{z | current_ct: ct}
  end

  def end_container(%__MODULE__{current_ct: ct, containers: cts} = z) do
    %{z | containers: cts ++ [ct], current_ct: nil}
  end

  def add_env(%__MODULE__{current_ct: ct} = z, key, value) do
    env = ct.env ++ [{to_string(key), to_string(value)}]
    %{z | current_ct: %{ct | env: env}}
  end

  def add_file(%__MODULE__{current_ct: ct} = z, path, content) do
    files = Map.put(ct.files, to_string(path), content)
    %{z | current_ct: %{ct | files: files}}
  end

  def add_volume(%__MODULE__{current_ct: ct} = z, container_path, opts) do
    vol = %{
      container: to_string(container_path),
      host: to_string(Keyword.fetch!(opts, :host))
    }
    volumes = ct.volumes ++ [vol]
    %{z | current_ct: %{ct | volumes: volumes}}
  end

  def set_health_check(%__MODULE__{current_ct: ct} = z, type, opts) do
    hc = %{
      type: type,
      port: Keyword.fetch!(opts, :port),
      interval: Keyword.get(opts, :interval, 5000),
      retries: Keyword.get(opts, :retries, 3)
    }
    %{z | current_ct: %{ct | health_check: hc}}
  end

  def set_firewall_rules(%__MODULE__{current_ct: ct} = z, rules) do
    fw = %{chains: [%{rules: rules}]}
    %{z | current_ct: %{ct | firewall: fw}}
  end

  # --- Validation ---

  def validate!(%__MODULE__{} = z, image_names) do
    Enum.each(z.containers, fn ct ->
      if ct.binary == nil do
        raise CompileError,
          description: "container #{inspect(ct.name)}: missing binary"
      end

      if ct.image != nil and ct.image not in image_names do
        raise CompileError,
          description: "container #{inspect(ct.name)}: undeclared image #{inspect(ct.image)}. " <>
            "Declare it in the images block."
      end

      if ct.ip != nil do
        validate_ip_in_subnet!(ct.name, ct.ip, z.subnet, z.netmask)
      end
    end)

    # Duplicate container names
    names = Enum.map(z.containers, & &1.name)
    dupes = names -- Enum.uniq(names)
    if dupes != [] do
      raise CompileError,
        description: "duplicate container names in zone #{inspect(z.name)}: #{inspect(dupes)}"
    end

    # Validate allow :internet requires interface
    Enum.each(z.allows, fn
      {:internet, _via} -> :ok
      _ -> :ok
    end)

    :ok
  end

  defp validate_ip_in_subnet!(ct_name, {a, b, c, d}, {sa, sb, sc, _sd}, netmask)
       when netmask == 24 do
    if a != sa or b != sb or c != sc do
      raise CompileError,
        description: "container #{inspect(ct_name)}: IP {#{a},#{b},#{c},#{d}} " <>
          "outside zone subnet {#{sa},#{sb},#{sc},0}/#{netmask}"
    end
  end
  defp validate_ip_in_subnet!(_name, _ip, _subnet, _mask), do: :ok

  # --- Term output ---

  def to_term(%__MODULE__{} = z, images_builder) do
    containers =
      Enum.map(z.containers, fn ct ->
        ct_term = %{
          name: ct.name,
          binary: ct.binary,
          ip: ct.ip,
          ports: ct.ports,
          limits: ct.limits,
          restart: ct.restart,
          seccomp: ct.seccomp,
          uid: ct.uid,
          gid: ct.gid,
          args: ct.args,
          caps: ct.caps,
          env: ct.env,
          files: ct.files,
          volumes: ct.volumes
        }

        ct_term = if ct.image do
          case Erlkoenig.Images.Builder.resolve_path(images_builder, ct.image) do
            {:ok, path} ->
              Map.merge(ct_term, %{image: ct.image, image_path: path})
            {:error, _} ->
              Map.put(ct_term, :image, ct.image)
          end
        else
          ct_term
        end

        ct_term = if ct.health_check, do: Map.put(ct_term, :health_check, ct.health_check), else: ct_term
        ct_term = if ct.firewall, do: Map.put(ct_term, :firewall, ct.firewall), else: ct_term

        ct_term
        |> Enum.reject(fn {_k, v} -> v == nil or v == [] or v == %{} end)
        |> Map.new()
      end)

    zone_term = %{
      name: z.name,
      subnet: z.subnet,
      gateway: z.gateway,
      netmask: z.netmask,
      bridge: z.bridge,
      pool: %{start: z.pool_start, stop: z.pool_end},
      allows: z.allows,
      containers: containers
    }

    # Optional: interface
    zone_term = if z.interface,
      do: Map.put(zone_term, :interface, z.interface),
      else: zone_term

    zone_term
  end
end
