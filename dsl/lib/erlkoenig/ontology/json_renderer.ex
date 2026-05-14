#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

defmodule Erlkoenig.Ontology.JsonRenderer do
  @moduledoc """
  Convert an ontology `World` into a JSON-encodable list of fact maps.

  The DSL stores values that aren't natively JSON: atom keys, tuple
  IP addresses (`{10, 0, 0, 1}`), CIDR-tuples (`{10, 0, 0, 0, 24}`),
  arbitrary atoms. This module normalises them so `:json.encode/1`
  accepts the result without raising `{:unsupported_type, _}`.

  Output shape per fact:

      %{
        "type"       => "container",
        "id"         => "frontdoor/edge-0",
        "properties" => %{...stringified keys, jsonable values...},
        "links"      => [
          %{"rel" => "in_pod", "target_type" => "pod",
            "target_id" => "frontdoor"}
        ]
      }
  """

  alias Erlkoenig.Ontology.{Fact, World}

  @spec world_to_jsonable(World.t()) :: [map()]
  def world_to_jsonable(%World{facts: facts}) do
    Enum.map(facts, &fact_to_map/1)
  end

  defp fact_to_map(%Fact{ref: ref, properties: props, links: links}) do
    {type, id} = ref_pair(ref)

    %{
      "type" => Atom.to_string(type),
      "id" => to_string(id),
      "properties" => to_jsonable(props),
      "links" => Enum.map(links, &link_to_map/1)
    }
  end

  defp ref_pair({:external, t, i}), do: {t, i}
  defp ref_pair({t, i}), do: {t, i}

  defp link_to_map({rel, {:external, t, i}}) do
    %{
      "rel" => Atom.to_string(rel),
      "target_type" => Atom.to_string(t),
      "target_id" => to_string(i),
      "external" => true
    }
  end

  defp link_to_map({rel, {t, i}}) do
    %{
      "rel" => Atom.to_string(rel),
      "target_type" => Atom.to_string(t),
      "target_id" => to_string(i)
    }
  end

  # ------------------------------------------------------------------
  # Value normalisation
  # ------------------------------------------------------------------

  @doc false
  @spec to_jsonable(term()) :: term()
  def to_jsonable(v) when v in [true, false, nil], do: v
  def to_jsonable(v) when is_binary(v), do: v
  def to_jsonable(v) when is_number(v), do: v
  def to_jsonable(v) when is_atom(v), do: Atom.to_string(v)

  def to_jsonable({a, b, c, d})
      when is_integer(a) and a in 0..255 and is_integer(b) and b in 0..255 and
             is_integer(c) and c in 0..255 and is_integer(d) and d in 0..255 do
    "#{a}.#{b}.#{c}.#{d}"
  end

  def to_jsonable({a, b, c, d, prefix})
      when is_integer(a) and a in 0..255 and is_integer(b) and b in 0..255 and
             is_integer(c) and c in 0..255 and is_integer(d) and d in 0..255 and
             is_integer(prefix) and prefix in 0..32 do
    "#{a}.#{b}.#{c}.#{d}/#{prefix}"
  end

  def to_jsonable(t) when is_tuple(t), do: inspect(t)

  def to_jsonable(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {key_to_string(k), to_jsonable(v)} end)
  end

  def to_jsonable(list) when is_list(list) do
    Enum.map(list, &to_jsonable/1)
  end

  def to_jsonable(other), do: inspect(other)

  defp key_to_string(k) when is_binary(k), do: k
  defp key_to_string(k) when is_atom(k), do: Atom.to_string(k)
  defp key_to_string(k), do: to_string(k)
end
