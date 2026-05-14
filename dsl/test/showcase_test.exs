defmodule Mix.Tasks.Erlkoenig.ShowcaseTest do
  use ExUnit.Case, async: false

  alias Mix.Tasks.Erlkoenig.Showcase

  setup do
    # Each test recompiles the showcase stack — purge so a previous
    # test's beam doesn't shadow the source.
    :code.purge(ResourceAdmissionLab)
    :code.delete(ResourceAdmissionLab)
    :ok
  end

  describe "dispatch/2 — known showcase" do
    test "renders the resource_admission lab as Mermaid by default" do
      {:ok, output} = run(["resource_admission"])

      out = IO.iodata_to_binary(output)
      assert String.starts_with?(out, "graph TD\n")
      # Stack-level fact and at least one container show up.
      assert out =~ "stack__"
      assert out =~ "container__"
      # The lab declares per-container kill-factor edges via the
      # standard stack ontology — there should be plenty of `-->|`
      # edges.
      edge_count =
        out
        |> String.split("\n", trim: true)
        |> Enum.count(&String.contains?(&1, "-->|"))

      assert edge_count > 0
    end

    test "renders as JSON" do
      {:ok, output} = run(["resource_admission", "--format", "json"])

      decoded =
        output
        |> IO.iodata_to_binary()
        |> :json.decode()

      assert is_list(decoded)
      assert length(decoded) > 0
      types = decoded |> Enum.map(& &1["type"]) |> Enum.uniq()
      assert "stack" in types
      assert "container" in types
    end

    test "renders as text grouped by type" do
      {:ok, output} = run(["resource_admission", "--format", "text"])

      out = IO.iodata_to_binary(output)
      assert out =~ "Showcase ontology"
      assert out =~ "container ("
      assert out =~ "stack ("
    end

    test "renders a container ownership debug report" do
      {:ok, output} = run(["resource_admission", "--debug", "--format", "text"])

      out = IO.iodata_to_binary(output)
      assert out =~ "Ontology debug report"
      assert out =~ "scope summary:"
      assert out =~ "container-scope nft: 8 chains, 26 rules"
      assert out =~ "stack-global nft: 1 tables, 2 chains, 9 rules, 2 counters, 1 nflog_groups"
      assert out =~ "container frontdoor.edge-0"
      assert out =~ "pod: frontdoor"
      assert out =~ "zone: admission"
      assert out =~ "explains:"
      assert out =~ "nft_chain frontdoor.edge-0.input"
      assert out =~ "cleanup candidates:"
      assert out =~ "nft_rule frontdoor.edge-0.input.rule_1"
      assert out =~ "stack-global nft objects"
      assert out =~ "nft_table erlkoenig_host owner=host family=inet"
      assert out =~ "persistent while stack/host policy is active"
      assert out =~ "nft_counter erlkoenig_host.admission_input_drop"
      assert out =~ "nflog_group erlkoenig_host.72"
      assert out =~ "nft_chain erlkoenig_host.input"
      assert out =~ "nft_rule erlkoenig_host.input.rule_1"
    end
  end

  describe "dispatch/2 — error paths" do
    test "unknown showcase → exit 2" do
      assert {:error, 2, msg} = Showcase.dispatch(["bogus"], &noop/1)
      assert msg =~ "unknown showcase: bogus"
      assert msg =~ "Known:"
    end

    test "no args → usage" do
      assert {:error, 2, msg} = Showcase.dispatch([], &noop/1)
      assert msg =~ "Usage:"
    end

    test "--file to a missing path → exit 2" do
      assert {:error, 2, msg} =
               Showcase.dispatch(["--file", "/tmp/does-not-exist.exs"], &noop/1)

      assert msg =~ "file not found"
    end

    test "unknown --format → exit 2 (no silent fallback)" do
      assert {:error, 2, msg} =
               Showcase.dispatch(
                 ["resource_admission", "--format", "yaml"],
                 &noop/1
               )

      assert msg =~ "unknown --format"
      assert msg =~ "yaml"
      assert msg =~ "text | json | mermaid"
    end

    test "mistyped option name → exit 2 (not a silent default)" do
      # `--formt json` (typo on the flag, not the value) used to be
      # dropped by OptionParser and the default format kicked in.
      assert {:error, 2, msg} =
               Showcase.dispatch(
                 ["resource_admission", "--formt", "json"],
                 &noop/1
               )

      assert msg =~ "unknown option"
      assert msg =~ "--formt"
    end

    test "--debug rejects non-text formats" do
      assert {:error, 2, msg} =
               Showcase.dispatch(
                 ["resource_admission", "--debug", "--format", "json"],
                 &noop/1
               )

      assert msg =~ "--debug only supports --format text"
    end

    test "--debug and --explain are mutually exclusive" do
      assert {:error, 2, msg} =
               Showcase.dispatch(
                 ["resource_admission_denial", "--debug", "--explain", "--format", "text"],
                 &noop/1
               )

      assert msg =~ "--debug renders declared topology"
    end
  end

  describe "dispatch/2 — --explain mode (synthesised denial)" do
    setup do
      :code.purge(ResourceAdmissionDenialLab)
      :code.delete(ResourceAdmissionDenialLab)
      :ok
    end

    test "synthesises a denial world from declared limits" do
      {:ok, output} =
        run([
          "resource_admission_denial",
          "--explain",
          "--format",
          "mermaid"
        ])

      out = IO.iodata_to_binary(output)

      # The output is no longer the topology — it's the synthesised
      # admission-denial world with its causal facts.
      assert String.starts_with?(out, "graph TD\n")
      assert out =~ "admission_denial__"
      assert out =~ "capacity_snapshot__"
      assert out =~ "resource_holder__"
      assert out =~ "reason: insufficient_memory"
      # 8 GiB request from the lab — must show as compact bytes.
      assert out =~ "8.0G"
    end

    test "the synthesised world is rendered as JSON facts when asked" do
      {:ok, output} =
        run([
          "resource_admission_denial",
          "--explain",
          "--format",
          "json"
        ])

      decoded =
        output
        |> IO.iodata_to_binary()
        |> :json.decode()

      types = decoded |> Enum.map(& &1["type"]) |> Enum.uniq() |> MapSet.new()

      # All four denial-world fact types must appear; no `container`
      # facts (those are topology, not the explainer).
      assert MapSet.member?(types, "admission_denial")
      assert MapSet.member?(types, "resource_request")
      assert MapSet.member?(types, "capacity_snapshot")
      assert MapSet.member?(types, "resource_holder")
      refute MapSet.member?(types, "container")
    end

    test "rejects the last-declared container, not the first" do
      # The lab declares two workers in the order [worker-0, worker-1]
      # via `for_each i <- 0..1`. Synthesis must follow that
      # chronology: worker-0 grabbed the budget, worker-1 is the one
      # that would have been rejected. An earlier `Enum.sort_by(..., :desc)`
      # picked worker-0 instead because tie-breaking went to first-
      # declared, which inverted the operator-natural story.
      {:ok, output} =
        run([
          "resource_admission_denial",
          "--explain",
          "--format",
          "json"
        ])

      decoded =
        output
        |> IO.iodata_to_binary()
        |> :json.decode()

      [denial] = Enum.filter(decoded, &(&1["type"] == "admission_denial"))
      assert denial["properties"]["container_id"] == "worker-1"

      holder_ids =
        decoded
        |> Enum.filter(&(&1["type"] == "resource_holder"))
        |> Enum.map(&get_in(&1, ["properties", "holder_id"]))

      assert holder_ids == ["worker-0"]
    end

    test "synthesize_denial/1 returns error when no container has memory" do
      world = %Erlkoenig.Ontology.World{
        schema: Erlkoenig.Ontology.Schema.default(),
        facts: [
          %Erlkoenig.Ontology.Fact{
            ref: {:container, "x"},
            type: :container,
            properties: %{name: "x"},
            links: []
          }
        ]
      }

      assert {:error, msg} = Showcase.synthesize_denial(world)
      assert msg =~ "no containers with declared memory limits"
    end
  end

  # --- helpers ---

  defp run(args) do
    {:ok, io_pid} = Agent.start_link(fn -> [] end)

    write = fn data ->
      Agent.update(io_pid, fn acc -> [data | acc] end)
    end

    result = Showcase.dispatch(args, write)
    captured = Agent.get(io_pid, &Enum.reverse/1)
    Agent.stop(io_pid)

    case result do
      :ok -> {:ok, captured}
      other -> other
    end
  end

  defp noop(_), do: :ok
end
