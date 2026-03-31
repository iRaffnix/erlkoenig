defmodule Erlkoenig.Steering.Builder do
  @moduledoc """
  Accumulates BPF steering declarations (services + routes).

  Services define L4 DSR load balancing: VIP:port/proto → backend containers.
  Routes define L3 steering: container IP → ifindex (auto-resolved at deploy).

  Backend names and route targets reference declared container names.
  Resolution to ifindices happens at deploy time, not compile time.
  """

  defstruct services: [], routes: []

  def new, do: %__MODULE__{}

  def add_service(%__MODULE__{services: svcs} = b, name, opts) do
    svc = %{
      name: name,
      vip: Keyword.fetch!(opts, :vip),
      port: Keyword.fetch!(opts, :port),
      proto: Keyword.fetch!(opts, :proto),
      backends: Keyword.fetch!(opts, :backends) |> Enum.map(&to_string/1)
    }

    validate_proto!(svc.proto)
    validate_ip!(svc.vip)

    if svc.backends == [] do
      raise CompileError,
        description: "service #{inspect(name)}: backends must not be empty"
    end

    %{b | services: svcs ++ [svc]}
  end

  def add_route(%__MODULE__{routes: routes} = b, container_name) do
    %{b | routes: routes ++ [to_string(container_name)]}
  end

  def validate!(%__MODULE__{} = b, all_container_names) do
    # Check service backends reference declared containers
    Enum.each(b.services, fn svc ->
      Enum.each(svc.backends, fn backend ->
        if backend not in all_container_names do
          raise CompileError,
            description: "service #{inspect(svc.name)}: unknown backend #{inspect(backend)}. " <>
              "Must reference a declared container."
        end
      end)
    end)

    # Check routes reference declared containers
    Enum.each(b.routes, fn name ->
      if name not in all_container_names do
        raise CompileError,
          description: "steering route #{inspect(name)}: unknown container"
      end
    end)

    :ok
  end

  def to_term(%__MODULE__{services: svcs, routes: routes}) do
    %{
      services: Enum.map(svcs, fn s ->
        %{
          name: s.name,
          vip: s.vip,
          port: s.port,
          proto: s.proto,
          backends: s.backends
        }
      end),
      routes: routes
    }
  end

  defp validate_proto!(proto) when proto in [:tcp, :udp], do: :ok
  defp validate_proto!(proto) do
    raise CompileError,
      description: "invalid proto #{inspect(proto)}, must be :tcp or :udp"
  end

  defp validate_ip!({a, b, c, d})
       when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255, do: :ok
  defp validate_ip!(ip) do
    raise CompileError,
      description: "invalid IP #{inspect(ip)}, must be {0..255, 0..255, 0..255, 0..255}"
  end
end
