defmodule Mix.Tasks.Erlkoenig.ExplainTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Erlkoenig.Explain

  # Same wire-shape fixture as ontology_test.exs uses for from_emit_event.
  # Keep the two in sync.
  @event %{
    "type" => "ct",
    "reason" => "resource_admission_denied",
    "code" => "EK_CT_RESOURCE_ADMISSION_DENIED",
    "context" => "resource admission denied",
    "data" => %{
      "zone" => "zone_a",
      "reason" => %{
        "reason" => "insufficient_memory",
        "required" => 4_294_967_296,
        "available" => 2_147_483_648,
        "evidence" => %{
          "kind" => "memory",
          "ceiling" => 8_589_934_592,
          "allocated" => 5_368_709_120,
          "committed" => 1_073_741_824,
          "last_updated" => 1_778_486_220_000,
          "allocated_sources" => [
            %{"id" => "api-0", "name" => "api", "kind" => "memory",
              "value" => 2_147_483_648}
          ],
          "committed_sources" => [
            %{"id" => "api-1", "kind" => "memory",
              "value" => 1_073_741_824, "since_ms" => 1_778_486_219_100}
          ]
        }
      },
      "limits" => %{"memory" => 4_294_967_296, "pids" => 512}
    },
    "severity" => "error",
    "source" => %{},
    "ts_ms" => 1_778_486_220_000,
    "container" => "api-2"
  }

  describe "dispatch/3 — text format" do
    test "renders a structured trace" do
      json = :json.encode(@event) |> IO.iodata_to_binary()
      {:ok, output} = run(["admission"], json)

      output_str = IO.iodata_to_binary(output)
      assert output_str =~ "Admission denial trace"
      assert output_str =~ "admission_denial"
      assert output_str =~ "resource_request"
      assert output_str =~ "capacity_snapshot"
      assert output_str =~ "resource_holder"
      assert output_str =~ "api-2"
    end

    test "groups facts by type with a count" do
      json = :json.encode(@event) |> IO.iodata_to_binary()
      {:ok, output} = run(["admission"], json)

      output_str = IO.iodata_to_binary(output)
      # 1 denial, 2 requests (memory + pids), 1 snapshot,
      # 2 holders (1 allocated + 1 committed)
      assert output_str =~ "admission_denial (1)"
      assert output_str =~ "resource_request (2)"
      assert output_str =~ "capacity_snapshot (1)"
      assert output_str =~ "resource_holder (2)"
    end
  end

  describe "dispatch/3 — mermaid format" do
    test "emits a graph block consumable by Mermaid renderers" do
      json = :json.encode(@event) |> IO.iodata_to_binary()
      {:ok, output} = run(["admission", "--format", "mermaid"], json)

      out = IO.iodata_to_binary(output)
      assert String.contains?(out, "graph TD")
      # Reused — there's exactly one denial node, plus requests, snapshot,
      # and holders. Spot-check the meaningful relations come through.
      assert out =~ "-->|has_resource_request|"
      assert out =~ "-->|rejected_by_snapshot|"
      assert out =~ "-->|capacity_held_by|"
      # Compact byte formatting (large integers from the wire).
      assert out =~ "4.0G"
    end
  end

  describe "dispatch/3 — json format" do
    test "emits a JSON array of facts" do
      json = :json.encode(@event) |> IO.iodata_to_binary()
      {:ok, output} = run(["admission", "--format", "json"], json)

      decoded =
        output
        |> IO.iodata_to_binary()
        |> :json.decode()

      assert is_list(decoded)
      # Same fact count as the world.
      assert length(decoded) == 6

      types =
        decoded
        |> Enum.map(& &1["type"])
        |> Enum.frequencies()

      assert types["admission_denial"] == 1
      assert types["resource_request"] == 2
      assert types["capacity_snapshot"] == 1
      assert types["resource_holder"] == 2

      # The committed holder carries since_ms — the field added in
      # node_resources for "who holds capacity since when".
      [holder] =
        Enum.filter(decoded, fn f ->
          f["type"] == "resource_holder" and
            f["properties"]["class"] == "committed"
        end)

      assert holder["properties"]["since_ms"] == 1_778_486_219_100
    end
  end

  describe "dispatch/3 — error paths" do
    test "empty stdin → exit 2" do
      assert {:error, 2, msg} = Explain.dispatch(["admission"], fn -> :eof end, &noop/1)
      assert msg =~ "empty stdin"
    end

    test "invalid JSON → exit 2" do
      assert {:error, 2, msg} =
               Explain.dispatch(
                 ["admission"],
                 fn -> "not json {[" end,
                 &noop/1
               )

      assert msg =~ "not valid JSON"
    end

    test "wrong event shape → exit 2" do
      other = %{"type" => "ct", "reason" => "spawn_timeout"}
      json = :json.encode(other) |> IO.iodata_to_binary()

      assert {:error, 2, msg} =
               Explain.dispatch(["admission"], fn -> json end, &noop/1)

      assert msg =~ "EK_CT_RESOURCE_ADMISSION_DENIED"
    end

    test "unknown subcommand → exit 2" do
      assert {:error, 2, msg} =
               Explain.dispatch(["nope"], fn -> "" end, &noop/1)

      assert msg =~ "Usage:"
    end

    test "unknown --format → exit 2 (no silent fallback to text)" do
      json = :json.encode(@event) |> IO.iodata_to_binary()

      assert {:error, 2, msg} =
               Explain.dispatch(
                 ["admission", "--format", "mermaidd"],
                 fn -> json end,
                 &noop/1
               )

      assert msg =~ "unknown --format"
      assert msg =~ "mermaidd"
      assert msg =~ "text | json | mermaid"
    end

    test "mistyped option name → exit 2 (no silent default)" do
      # `--formt json` (typo on the flag) used to be dropped by
      # OptionParser and the default format kicked in.
      json = :json.encode(@event) |> IO.iodata_to_binary()

      assert {:error, 2, msg} =
               Explain.dispatch(
                 ["admission", "--formt", "json"],
                 fn -> json end,
                 &noop/1
               )

      assert msg =~ "unknown option"
      assert msg =~ "--formt"
    end
  end

  # --- helpers ---

  defp run(args, stdin_body) do
    {:ok, io_pid} = Agent.start_link(fn -> [] end)

    write = fn data ->
      Agent.update(io_pid, fn acc -> [data | acc] end)
    end

    result = Explain.dispatch(args, fn -> stdin_body end, write)
    captured = Agent.get(io_pid, &Enum.reverse/1)
    Agent.stop(io_pid)

    case result do
      :ok -> {:ok, captured}
      other -> other
    end
  end

  defp noop(_), do: :ok
end
