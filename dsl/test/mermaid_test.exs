defmodule Erlkoenig.Ontology.MermaidTest do
  use ExUnit.Case, async: true

  alias Erlkoenig.Ontology.{Compiler, Fact, Mermaid, World}

  @denial_input %{
    container_id: "api-2",
    limits: %{memory: 4_294_967_296, pids: 512},
    reason: %{
      reason: :insufficient_memory,
      required: 4_294_967_296,
      available: 2_147_483_648,
      evidence: %{
        kind: :memory,
        ceiling: 8_589_934_592,
        allocated: 5_368_709_120,
        committed: 1_073_741_824,
        last_updated: 1_778_486_220_000,
        allocated_sources: [
          %{id: "api-0", name: "api", kind: :memory, value: 2_147_483_648}
        ],
        committed_sources: [
          %{id: "api-1", kind: :memory, value: 1_073_741_824,
            since_ms: 1_778_486_219_100}
        ]
      }
    }
  }

  describe "render/2" do
    test "produces a `graph TD` block by default" do
      world = Compiler.from_admission_denial(@denial_input)
      out = Mermaid.render(world) |> IO.iodata_to_binary()

      assert String.starts_with?(out, "graph TD\n")
    end

    test "honors :direction option" do
      world = Compiler.from_admission_denial(@denial_input)
      out = Mermaid.render(world, direction: "LR") |> IO.iodata_to_binary()

      assert String.starts_with?(out, "graph LR\n")
    end

    test "every fact becomes a node line" do
      world = Compiler.from_admission_denial(@denial_input)
      out = Mermaid.render(world) |> IO.iodata_to_binary()

      # 1 denial + 2 requests + 1 snapshot + 2 holders = 6 nodes.
      node_lines =
        out
        |> String.split("\n", trim: true)
        |> Enum.filter(&Regex.match?(~r/^\s+\w+__\w+\[/, &1))

      assert length(node_lines) == 6
    end

    test "every link becomes an edge with relation label" do
      world = Compiler.from_admission_denial(@denial_input)
      out = Mermaid.render(world) |> IO.iodata_to_binary()

      # 2 has_resource_request + 1 rejected_by_snapshot + 2 capacity_held_by = 5
      edge_count =
        out
        |> String.split("\n", trim: true)
        |> Enum.count(&String.contains?(&1, "-->|"))

      assert edge_count == 5
      assert out =~ "-->|has_resource_request|"
      assert out =~ "-->|rejected_by_snapshot|"
      assert out =~ "-->|capacity_held_by|"
    end

    test "formats large integers compactly in labels" do
      world = Compiler.from_admission_denial(@denial_input)
      out = Mermaid.render(world) |> IO.iodata_to_binary()

      # 4_294_967_296 should render as 4.0G, not as the literal 10-digit blob.
      assert out =~ "4.0G"
      assert out =~ "8.0G"
      refute out =~ "4294967296"
    end

    test "labels carry per-type summaries (denial reason, snapshot fields)" do
      world = Compiler.from_admission_denial(@denial_input)
      out = Mermaid.render(world) |> IO.iodata_to_binary()

      assert out =~ "reason: insufficient_memory"
      assert out =~ "ceiling:"
      assert out =~ "allocated:"
      assert out =~ "committed:"
    end

    test "node ids are deterministic and ascii-safe" do
      world = Compiler.from_admission_denial(@denial_input)
      out1 = Mermaid.render(world) |> IO.iodata_to_binary()
      out2 = Mermaid.render(world) |> IO.iodata_to_binary()

      assert out1 == out2
      # `api-2/denial` becomes `admission_denial__api_2_denial_<hash>`.
      assert out1 =~ "admission_denial__api_2_denial_"
    end

    test "node ids stay distinct when stripping non-alnum chars would collide" do
      # Three refs whose original ids differ only in punctuation. The
      # naive substitution `[^A-Za-z0-9] -> _` would map all three to
      # `host__zone_a_pod_1`, silently merging them in the diagram.
      facts =
        for id <- ["zone-a/pod-1", "zone_a/pod_1", "zone/a-pod/1"] do
          %Fact{
            ref: {:host, id},
            type: :host,
            properties: %{name: id},
            links: []
          }
        end

      world = %World{schema: Erlkoenig.Ontology.Schema.default(), facts: facts}
      out = Mermaid.render(world) |> IO.iodata_to_binary()

      # Pull out every node id from the output (lines of the form
      # `  <id>["..."]`) and assert the multiset is unique.
      ids =
        out
        |> String.split("\n", trim: true)
        |> Enum.flat_map(fn line ->
          case Regex.run(~r/^\s+([A-Za-z0-9_]+)\["/, line) do
            [_, id] -> [id]
            _ -> []
          end
        end)

      assert length(ids) == 3
      assert length(Enum.uniq(ids)) == 3
    end

    test "tolerates string-keyed properties (wire path from JSON)" do
      # Build a hand-rolled fact with string keys (what JSON decoding
      # produces) instead of atoms, and ensure the renderer doesn't crash
      # and still produces a meaningful summary.
      fact = %Fact{
        ref: {:capacity_snapshot, "x/snap"},
        type: :capacity_snapshot,
        properties: %{
          "kind" => "memory",
          "ceiling" => 1024,
          "allocated" => 512,
          "committed" => 256
        },
        links: []
      }

      world = %World{schema: Erlkoenig.Ontology.Schema.default(), facts: [fact]}
      out = Mermaid.render(world) |> IO.iodata_to_binary()

      assert out =~ "ceiling: 1.0K"
      assert out =~ "kind: memory"
    end
  end

  describe "subgraph/3" do
    test "keeps only the requested refs" do
      world = Compiler.from_admission_denial(@denial_input)

      out =
        Mermaid.subgraph(world, [
          {:admission_denial, "api-2/denial"},
          {:capacity_snapshot, "api-2/snapshot"}
        ])
        |> IO.iodata_to_binary()

      assert out =~ "admission_denial__api_2_denial"
      assert out =~ "capacity_snapshot__api_2_snapshot"
      # Holders excluded.
      refute out =~ "resource_holder__"
    end
  end
end
