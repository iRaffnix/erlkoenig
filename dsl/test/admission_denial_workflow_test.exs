defmodule AdmissionDenialWorkflowTest do
  @moduledoc """
  End-to-end functional test for the admission-denial explain pipe.

  Composes everything WP1+WP2+WP3 produced:

      DSL stack file (ResourceAdmissionDenialLab)
        ↓ compile
      Module.ontology()  →  declared topology
        ↓
      simulated EK_CT_RESOURCE_ADMISSION_DENIED event
        ↓ Compiler.from_emit_event/1
      causal World
        ↓ Mermaid.render/1
      Mermaid graph an operator can paste into a doc

  The runtime side (erlkoenig_node_resources, ek admission denial)
  is exercised in the Erlang test suite. This test verifies the
  Elixir half: that a payload shaped like the runtime's actually
  flows through the explain pipe and produces a useful diagram.
  """
  use ExUnit.Case, async: false

  alias Erlkoenig.Ontology.{Compiler, Mermaid, World}

  setup do
    :code.purge(ResourceAdmissionDenialLab)
    :code.delete(ResourceAdmissionDenialLab)
    :ok
  end

  test "denial-lab compiles, ontology emits two worker containers" do
    [{module, _}] =
      Code.compile_file("../examples/showcase/resource_admission_denial_lab.exs")

    %World{} = world = module.ontology()

    workers =
      Enum.filter(world.facts, fn f ->
        f.type == :container and
          Map.get(f.properties, :name) in ["worker-0", "worker-1"]
      end)

    assert length(workers) == 2

    # Each replica declared 8 GiB. The fact carries the limit map
    # the operator wrote — the runtime later compares this against
    # `containers_memory_max` and rejects.
    Enum.each(workers, fn w ->
      limits = Map.get(w.properties, :limits, %{})
      assert Map.get(limits, :memory) == 8 * 1024 * 1024 * 1024
      assert Map.get(limits, :pids) == 256
    end)
  end

  test "simulated denial event renders a causal Mermaid graph" do
    # The exact wire shape the runtime would produce when worker-1
    # is rejected. Field names match `erlkoenig_error:to_map/1`
    # output (binary keys after JSON round-trip) so this exercises
    # the production path, not a hand-tuned input shape.
    event = denial_event_for("worker-1")

    %World{} = world = Compiler.from_emit_event(event)

    out = Mermaid.render(world) |> IO.iodata_to_binary()

    # The diagram should:
    #   1. announce itself as a Mermaid graph,
    #   2. surface the rejected container's id,
    #   3. surface the kill-factor that tripped (memory),
    #   4. show the holders that ate the budget,
    #   5. format byte values compactly so labels stay readable.
    assert String.starts_with?(out, "graph TD\n")
    assert out =~ "worker_1"
    assert out =~ "reason: insufficient_memory"
    assert out =~ "8.0G"
    assert out =~ "worker_0"
    assert out =~ "in_flight_starter"
    assert out =~ "-->|rejected_by_snapshot|"
    assert out =~ "-->|capacity_held_by|"
  end

  test "denial event also passes through the explain mix task" do
    event = denial_event_for("worker-1")
    json = :json.encode(event) |> IO.iodata_to_binary()

    {:ok, captured} = run_explain(["admission", "--format", "mermaid"], json)

    out = IO.iodata_to_binary(captured)
    assert String.starts_with?(out, "graph TD\n")
    assert out =~ "worker_1"
    assert out =~ "8.0G"
  end

  # --- fixtures and helpers ---

  defp denial_event_for(container_id) do
    %{
      "type" => "ct",
      "reason" => "resource_admission_denied",
      "code" => "EK_CT_RESOURCE_ADMISSION_DENIED",
      "context" => "resource admission denied",
      "data" => %{
        "zone" => "denial",
        "reason" => %{
          "reason" => "insufficient_memory",
          "required" => 8 * 1024 * 1024 * 1024,
          "available" => 1 * 1024 * 1024 * 1024,
          "evidence" => %{
            "kind" => "memory",
            "ceiling" => 8 * 1024 * 1024 * 1024,
            "allocated" => 7 * 1024 * 1024 * 1024,
            "committed" => 0,
            "last_updated" => 1_778_500_000_000,
            "allocated_sources" => [
              %{
                "id" => "worker-0",
                "name" => "worker",
                "kind" => "memory",
                "value" => 7 * 1024 * 1024 * 1024
              }
            ],
            "committed_sources" => [
              %{
                "id" => "in_flight_starter",
                "kind" => "memory",
                "value" => 0,
                "since_ms" => 1_778_499_999_500
              }
            ]
          }
        },
        "limits" => %{
          "memory" => 8 * 1024 * 1024 * 1024,
          "pids" => 256
        }
      },
      "severity" => "error",
      "source" => %{},
      "ts_ms" => 1_778_500_000_000,
      "container" => container_id
    }
  end

  defp run_explain(args, stdin_body) do
    {:ok, io_pid} = Agent.start_link(fn -> [] end)

    write = fn data ->
      Agent.update(io_pid, fn acc -> [data | acc] end)
    end

    result =
      Mix.Tasks.Erlkoenig.Explain.dispatch(args, fn -> stdin_body end, write)

    captured = Agent.get(io_pid, &Enum.reverse/1)
    Agent.stop(io_pid)

    case result do
      :ok -> {:ok, captured}
      other -> other
    end
  end
end
