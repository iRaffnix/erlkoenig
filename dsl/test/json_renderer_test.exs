defmodule Erlkoenig.Ontology.JsonRendererTest do
  use ExUnit.Case, async: true

  alias Erlkoenig.Ontology.{Fact, JsonRenderer, Schema, World}

  describe "to_jsonable/1" do
    test "atoms become strings" do
      assert JsonRenderer.to_jsonable(:insufficient_memory) ==
               "insufficient_memory"
    end

    test "true/false/nil pass through unchanged" do
      assert JsonRenderer.to_jsonable(true) == true
      assert JsonRenderer.to_jsonable(false) == false
      assert JsonRenderer.to_jsonable(nil) == nil
    end

    test "IPv4 4-tuples become dotted strings" do
      assert JsonRenderer.to_jsonable({10, 72, 0, 1}) == "10.72.0.1"
      assert JsonRenderer.to_jsonable({192, 168, 1, 1}) == "192.168.1.1"
    end

    test "CIDR 5-tuples become subnet strings" do
      assert JsonRenderer.to_jsonable({10, 72, 0, 0, 24}) == "10.72.0.0/24"
    end

    test "other tuples become inspect strings" do
      assert JsonRenderer.to_jsonable({:ok, 1}) == "{:ok, 1}"
    end

    test "maps stringify keys and recurse on values" do
      assert JsonRenderer.to_jsonable(%{
               name: :foo,
               ip: {10, 0, 0, 1},
               nested: %{port: 80}
             }) == %{
               "name" => "foo",
               "ip" => "10.0.0.1",
               "nested" => %{"port" => 80}
             }
    end

    test "lists recurse on elements" do
      assert JsonRenderer.to_jsonable([:a, {10, 0, 0, 1}, %{k: :v}]) ==
               ["a", "10.0.0.1", %{"k" => "v"}]
    end

    test "numbers and binaries pass through" do
      assert JsonRenderer.to_jsonable(42) == 42
      assert JsonRenderer.to_jsonable(1.5) == 1.5
      assert JsonRenderer.to_jsonable("hello") == "hello"
    end
  end

  describe "world_to_jsonable/1" do
    test "round-trips through :json.encode/1 without unsupported_type" do
      fact = %Fact{
        ref: {:zone, "admission"},
        type: :zone,
        properties: %{
          subnet: {10, 72, 0, 0, 24},
          gateway: {10, 72, 0, 1},
          mode: :l3s
        },
        links: [{:has_zone, {:host, "host"}}]
      }

      world = %World{schema: Schema.default(), facts: [fact]}

      # The bug we fixed: :json.encode/1 chokes on tuples. After
      # to_jsonable normalisation, the encode succeeds.
      payload = JsonRenderer.world_to_jsonable(world)
      encoded = :json.encode(payload) |> IO.iodata_to_binary()

      decoded = :json.decode(encoded)
      assert is_list(decoded)
      [f] = decoded
      assert f["properties"]["subnet"] == "10.72.0.0/24"
      assert f["properties"]["gateway"] == "10.72.0.1"
      assert f["properties"]["mode"] == "l3s"
    end

    test "external refs carry external: true" do
      fact = %Fact{
        ref: {:container, "x"},
        type: :container,
        properties: %{},
        links: [{:in_pod, {:external, :pod, "ext-pod"}}]
      }

      world = %World{schema: Schema.default(), facts: [fact]}

      [f] = JsonRenderer.world_to_jsonable(world)
      [link] = f["links"]
      assert link["external"] == true
      assert link["target_type"] == "pod"
      assert link["target_id"] == "ext-pod"
    end
  end
end
