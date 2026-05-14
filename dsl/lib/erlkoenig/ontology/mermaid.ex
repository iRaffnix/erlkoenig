#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

defmodule Erlkoenig.Ontology.Mermaid do
  @moduledoc """
  Render an ontology `World` as Mermaid graph syntax.

  The output is plain text suitable for embedding in Markdown via a
  ` ```mermaid ` fence, or rendering at https://mermaid.live.

  Node ids are deterministic and ascii-safe so the same `World`
  always produces the same diagram (snapshot-friendly). Per-type
  property summaries keep the labels readable instead of dumping the
  whole properties map.
  """

  alias Erlkoenig.Ontology.{Fact, World}

  @type opts :: [direction: String.t()]

  @doc """
  Render the world as a Mermaid `graph` block.

  Options:

    * `:direction` — Mermaid layout, one of `"TD"`, `"LR"`, `"BT"`,
      `"RL"`. Default `"TD"` (top-down — natural for causal trees).
  """
  @spec render(World.t(), opts()) :: iodata()
  def render(world, opts \\ [])

  def render(%World{facts: facts}, opts) do
    direction = Keyword.get(opts, :direction, "TD")

    [
      "graph ", direction, ?\n,
      Enum.map(facts, &node_line/1),
      Enum.flat_map(facts, &edge_lines/1)
    ]
  end

  @doc """
  Render only the facts whose ref is in `refs` (and their direct
  link-targets when those targets are also in the world).

  Useful for focused explanations — e.g. a single admission denial
  with only the relevant snapshot and holders, not the full world.
  """
  @spec subgraph(World.t(), [Fact.ref()], opts()) :: iodata()
  def subgraph(%World{facts: all_facts} = world, refs, opts \\ []) do
    keep = MapSet.new(refs)
    filtered = Enum.filter(all_facts, fn f -> MapSet.member?(keep, f.ref) end)
    render(%{world | facts: filtered}, opts)
  end

  # ------------------------------------------------------------------
  # Nodes
  # ------------------------------------------------------------------

  defp node_line(%Fact{ref: ref, type: type, properties: props}) do
    [
      "  ",
      node_id(ref),
      "[\"",
      escape(node_label(type, ref, props)),
      "\"]\n"
    ]
  end

  defp node_label(type, {_t, id}, props) do
    header = "#{type}: #{id}"

    case prop_summary(type, props) do
      "" -> header
      summary -> header <> "\n" <> summary
    end
  end

  # Per-type compact label so the diagram is readable. Tolerates both
  # atom and string keys (atom from in-process Erlang→Elixir path,
  # string from JSON wire path).
  defp prop_summary(:admission_denial, p) do
    reason = pget(p, :reason) |> short()
    required = pget(p, :required)
    available = pget(p, :available)
    parts =
      [
        if(reason, do: "reason: #{reason}", else: nil),
        if(required, do: "required: #{format_value(required)}", else: nil),
        if(available, do: "available: #{format_value(available)}", else: nil)
      ]
      |> Enum.reject(&is_nil/1)

    Enum.join(parts, "\n")
  end

  defp prop_summary(:resource_request, p) do
    "#{pget(p, :kind) |> short()}: #{format_value(pget(p, :value))}"
  end

  defp prop_summary(:capacity_snapshot, p) do
    [
      "kind: #{pget(p, :kind) |> short()}",
      "ceiling: #{format_value(pget(p, :ceiling))}",
      "allocated: #{format_value(pget(p, :allocated))}",
      "committed: #{format_value(pget(p, :committed))}"
    ]
    |> Enum.join("\n")
  end

  defp prop_summary(:resource_holder, p) do
    base =
      "#{pget(p, :class) |> short()} #{pget(p, :kind) |> short()}\n" <>
        "#{pget(p, :holder_id)}: #{format_value(pget(p, :value))}"

    case pget(p, :since_ms) do
      nil -> base
      ms -> base <> "\nsince_ms: #{ms}"
    end
  end

  defp prop_summary(_, _), do: ""

  # ------------------------------------------------------------------
  # Edges
  # ------------------------------------------------------------------

  defp edge_lines(%Fact{ref: source_ref, links: links}) do
    src = node_id(source_ref)

    Enum.map(links, fn {relation, target_ref} ->
      [
        "  ",
        src,
        " -->|",
        Atom.to_string(relation),
        "| ",
        node_id(target_ref),
        ?\n
      ]
    end)
  end

  # ------------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------------

  defp node_id({:external, type, id}) do
    "ext__" <> to_string(type) <> "__" <> encoded_id(id)
  end

  defp node_id({type, id}) do
    to_string(type) <> "__" <> encoded_id(id)
  end

  # Mermaid node ids must be alphanumeric (plus `_`). The naive
  # approach of substituting every non-alnum character with `_`
  # is *not* injective: `api-1`, `api_1`, `api/1` all collapse to
  # `api_1`, which silently merges what the ontology had as three
  # distinct refs.
  #
  # Fix: keep an alnum/underscore prefix for human readability
  # *and* append a stable hash suffix of the original input. The
  # suffix is 12 hex chars (48 bits) — the birthday-collision
  # threshold sits around 16M entries, comfortably above any
  # realistic world size on a single host. For long-lived diagrams
  # of cluster-scale ontologies, swap to a longer prefix or to
  # a reversible encoding.
  defp encoded_id(id) do
    raw = to_string(id)
    alnum = String.replace(raw, ~r/[^A-Za-z0-9]/, "_")
    hash = short_hash(raw)
    alnum <> "_" <> hash
  end

  defp short_hash(raw) do
    :crypto.hash(:sha256, raw)
    |> Base.encode16(case: :lower)
    |> binary_part(0, 12)
  end

  # Mermaid label characters that need escaping inside a quoted label.
  defp escape(text) do
    text
    |> to_string()
    |> String.replace("\"", "&quot;")
    |> String.replace("\n", "<br/>")
  end

  defp pget(map, key) when is_map(map) do
    Map.get(map, key) || Map.get(map, Atom.to_string(key))
  end

  defp short(nil), do: nil
  defp short(v) when is_atom(v), do: Atom.to_string(v)
  defp short(v) when is_binary(v), do: v
  defp short(v), do: inspect(v)

  # Bytes/numbers formatted compactly so 4_294_967_296 reads as 4.0G,
  # not as a 10-digit blob inside a Mermaid node label.
  defp format_value(nil), do: "?"
  defp format_value(n) when is_integer(n) and n >= 1_073_741_824 do
    fmt(n / 1_073_741_824, "G")
  end
  defp format_value(n) when is_integer(n) and n >= 1_048_576 do
    fmt(n / 1_048_576, "M")
  end
  defp format_value(n) when is_integer(n) and n >= 1024 do
    fmt(n / 1024, "K")
  end
  defp format_value(n) when is_integer(n), do: Integer.to_string(n)
  defp format_value(v), do: inspect(v)

  defp fmt(f, suffix) do
    :io_lib.format("~.1f~s", [f, suffix]) |> IO.iodata_to_binary()
  end
end
