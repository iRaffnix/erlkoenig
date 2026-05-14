defmodule Erlkoenig.ShowcaseResourceAdmissionTest do
  use ExUnit.Case, async: false

  alias Erlkoenig.Ontology.World

  @showcase Path.expand("../../examples/showcase/resource_admission_lab.exs", __DIR__)

  setup_all do
    [{mod, _} | _] = Code.compile_file(@showcase)
    {:ok, module: mod, config: mod.config(), ontology: mod.ontology()}
  end

  test "showcase is a real two-pod resource-admission lab", %{config: c} do
    assert [zone] = c.zones
    assert zone.name == "admission"
    assert zone.subnet == {10, 72, 0, 0}

    assert Enum.map(c.pods, & &1.name) == ["frontdoor", "workers"]
    assert Enum.map(c.pods, & &1.strategy) == [:one_for_one, :rest_for_one]
  end

  test "all container instances are explicit and carry kill-factor limits", %{config: c} do
    containers = Enum.flat_map(c.pods, & &1.containers)
    names = Enum.map(containers, & &1.name)

    assert names == ["edge-0", "edge-1", "worker-0", "worker-1"]
    assert Enum.all?(containers, &(&1.replicas == 1))
    assert Enum.all?(containers, &is_integer(&1.limits.memory))
    assert Enum.all?(containers, &is_integer(&1.limits.pids))
    assert Enum.all?(containers, &is_integer(&1.limits.cpu))

    total_memory = Enum.reduce(containers, 0, &(&1.limits.memory + &2))
    total_pids = Enum.reduce(containers, 0, &(&1.limits.pids + &2))

    assert total_memory == 448_000_000
    assert total_pids == 320
  end

  test "host forward chain owns cross-container policy without runtime IP wait", %{config: c} do
    [table] = c.nft_tables
    forward = Enum.find(table.chains, &(&1.name == "forward"))
    assert forward != nil

    assert Enum.any?(forward.rules, fn
             {:accept,
              %{
                ip_saddr: {10, 72, 0, 0, 24},
                ip_daddr: {10, 72, 0, 0, 24},
                tcp_dport: 8080
              }} ->
               true

             _ ->
               false
           end)
  end

  test "ontology exposes stack, zone, containers and resource metadata", %{
    ontology: ontology
  } do
    assert %World{} = ontology

    by_type = Enum.frequencies_by(ontology.facts, & &1.type)
    assert by_type.stack == 1
    assert by_type.zone == 1
    assert by_type.pod == 2
    assert by_type.container == 4
    assert by_type.capability == 8
    assert by_type.publish == 4

    edge =
      Enum.find(ontology.facts, fn fact ->
        fact.ref == {:container, "frontdoor.edge-0"}
      end)

    assert edge.properties.limits.memory == 96_000_000
    assert edge.properties.limits.pids == 64
    assert edge.properties.limits.cpu == 50
  end
end
