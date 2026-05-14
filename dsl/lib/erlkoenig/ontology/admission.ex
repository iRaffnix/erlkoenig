defmodule Erlkoenig.Ontology.Admission do
  @moduledoc """
  Builds diagnostic ontology worlds for resource-admission denials.

  This module is deliberately diagnostic-only. Runtime admission stays in
  Erlang/ETS; the ontology world is built after a denial so operator tooling can
  explain which request was rejected, which snapshot was read, and which
  containers held capacity.
  """

  alias Erlkoenig.Ontology.{Fact, Schema, World}

  @type denial_input :: map()

  @doc """
  Build a diagnostic world from an `erlkoenig_error:to_map/1` payload.

  Pattern-matches strictly on the AMQP wire shape produced by the
  Erlang side when emitting `EK_CT_RESOURCE_ADMISSION_DENIED`. Other
  event shapes return `{:error, {:unknown_event_shape, event}}` so
  callers fail loud rather than silently building an empty world.

  Use this when the input came from JSON (e.g. `ek admission denial
  <id> --format json`); use `from_denial/1` directly when you have an
  already-shaped Elixir map.
  """
  @spec from_emit_event(map()) :: World.t() | {:error, term()}
  def from_emit_event(
        %{"type" => "ct", "reason" => "resource_admission_denied",
          "data" => data, "container" => container} = event
      )
      when is_map(data) and is_binary(container) do
    from_denial(%{
      container_id: container,
      limits: Map.get(data, "limits", %{}),
      reason: Map.get(data, "reason", %{}),
      ts_ms: Map.get(event, "ts_ms")
    })
  end

  def from_emit_event(other), do: {:error, {:unknown_event_shape, other}}

  @spec from_denial(denial_input()) :: World.t()
  def from_denial(input) when is_map(input) do
    id = input |> get_any([:container_id, "container_id", :id, "id"], "unknown") |> to_id()
    denial = get_any(input, [:reason, "reason", :denial, "denial"], input)
    limits = get_any(input, [:limits, "limits"], %{})
    reason = get_any(denial, [:reason, "reason"], :unknown)
    evidence = get_any(denial, [:evidence, "evidence"], %{})

    denial_ref = {:admission_denial, namespace(id, "denial")}
    snapshot_ref = {:capacity_snapshot, namespace(id, "snapshot")}

    facts =
      []
      |> add_denial(denial_ref, id, reason, denial)
      |> add_requests(denial_ref, id, limits)
      |> add_snapshot(denial_ref, snapshot_ref, evidence)
      |> add_holders(snapshot_ref, id, evidence, :allocated)
      |> add_holders(snapshot_ref, id, evidence, :committed)
      |> Enum.reverse()

    World.new(facts, Schema.default())
  end

  defp add_denial(facts, denial_ref, id, reason, denial) do
    [
      fact(
        :admission_denial,
        elem(denial_ref, 1),
        %{
          container_id: id,
          reason: reason,
          required: get_any(denial, [:required, "required"]),
          available: get_any(denial, [:available, "available"])
        }
        |> drop_nil(),
        []
      )
      | facts
    ]
  end

  defp add_requests(facts, denial_ref, id, limits) do
    limits
    |> limit_pairs()
    |> Enum.reduce(facts, fn {kind, value}, acc ->
      [
        fact(
          :resource_request,
          namespace(id, "request-#{kind}"),
          %{container_id: id, kind: kind, value: value},
          [{:has_resource_request, denial_ref}]
        )
        | acc
      ]
    end)
  end

  defp add_snapshot(facts, denial_ref, snapshot_ref, evidence) do
    [
      fact(
        :capacity_snapshot,
        elem(snapshot_ref, 1),
        %{
          kind: get_any(evidence, [:kind, "kind"]),
          ceiling: get_any(evidence, [:ceiling, "ceiling"]),
          allocated: get_any(evidence, [:allocated, "allocated"]),
          committed: get_any(evidence, [:committed, "committed"]),
          last_updated: get_any(evidence, [:last_updated, "last_updated"])
        }
        |> drop_nil(),
        [{:rejected_by_snapshot, denial_ref}]
      )
      | facts
    ]
  end

  defp add_holders(facts, snapshot_ref, id, evidence, class) do
    key = :"#{class}_sources"

    evidence
    |> get_any([key, Atom.to_string(key)], [])
    |> Enum.with_index()
    |> Enum.reduce(facts, fn {source, index}, acc ->
      kind = get_any(source, [:kind, "kind"], :unknown)
      holder_id = source |> get_any([:id, "id"], "holder-#{index}") |> to_id()

      [
        fact(
          :resource_holder,
          namespace(id, "#{class}-#{kind}-#{holder_id}-#{index}"),
          %{
            class: class,
            holder_id: holder_id,
            holder_name: get_any(source, [:name, "name"]),
            kind: kind,
            value: get_any(source, [:value, "value"]),
            since_ms: get_any(source, [:since_ms, "since_ms"])
          }
          |> drop_nil(),
          [{:capacity_held_by, snapshot_ref}]
        )
        | acc
      ]
    end)
  end

  defp fact(type, id, properties, links) do
    %Fact{ref: {type, id}, type: type, properties: properties, links: links}
  end

  defp limit_pairs(limits) when is_map(limits) do
    [:memory, :pids]
    |> Enum.flat_map(fn key ->
      case get_any(limits, [key, Atom.to_string(key)]) do
        value when is_integer(value) and value > 0 -> [{key, value}]
        _ -> []
      end
    end)
  end

  defp limit_pairs(_), do: []

  defp get_any(map, keys, default \\ nil)

  defp get_any(map, keys, default) when is_map(map) and is_list(keys) do
    Enum.find_value(keys, default, fn key ->
      case Map.fetch(map, key) do
        {:ok, value} -> value
        :error -> false
      end
    end)
  end

  defp get_any(_value, _keys, default), do: default

  defp drop_nil(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp namespace(prefix, suffix), do: "#{prefix}/#{suffix}"

  defp to_id(value) when is_binary(value), do: value
  defp to_id(value) when is_atom(value), do: Atom.to_string(value)
  defp to_id(value), do: to_string(value)
end
