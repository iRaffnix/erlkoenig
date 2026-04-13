defmodule HostIpvlanTest do
  use ExUnit.Case, async: true

  alias Erlkoenig.Host.Builder

  describe "add_ipvlan/3" do
    test "creates ipvlan entry with required fields" do
      h = Builder.new()
      |> Builder.add_ipvlan("edge", parent: {:device, "eth0"}, subnet: {10, 20, 0, 0, 24})

      assert [ipv] = h.ipvlans
      assert ipv.name == "edge"
      assert ipv.parent == "eth0"
      assert ipv.parent_type == :device
      assert ipv.subnet == {10, 20, 0, 0}
      assert ipv.netmask == 24
      assert ipv.ipvlan_mode == :l3s
      assert ipv.gateway == nil
    end

    test "respects explicit mode and gateway" do
      h = Builder.new()
      |> Builder.add_ipvlan("prod", parent: {:device, "bond0"}, subnet: {172, 16, 0, 0, 24},
                            mode: :l3, gateway: {172, 16, 0, 1})

      [ipv] = h.ipvlans
      assert ipv.ipvlan_mode == :l3
      assert ipv.gateway == {172, 16, 0, 1}
      assert ipv.netmask == 24
    end

    test "dummy parent type" do
      h = Builder.new()
      |> Builder.add_ipvlan("internal", parent: {:dummy, "ek_ct0"}, subnet: {10, 50, 0, 0, 24})

      [ipv] = h.ipvlans
      assert ipv.parent == "ek_ct0"
      assert ipv.parent_type == :dummy
    end

    test "rejects bare string parent" do
      assert_raise CompileError, ~r/must be.*dummy.*device/, fn ->
        Builder.new()
        |> Builder.add_ipvlan("x", parent: "eth0", subnet: {10, 0, 0, 0, 24})
      end
    end

    test "rejects non-/24 netmask" do
      assert_raise CompileError, ~r/only \/24 subnets/, fn ->
        Builder.new()
        |> Builder.add_ipvlan("x", parent: {:device, "eth0"}, subnet: {10, 0, 0, 0, 16})
      end
    end

    test "default netmask is 24 when not in subnet tuple" do
      h = Builder.new()
      |> Builder.add_ipvlan("x", parent: {:device, "eth0"}, subnet: {10, 0, 0, 0})

      [ipv] = h.ipvlans
      assert ipv.netmask == 24
    end
  end

  describe "validate!/3" do
    test "allows ipvlan" do
      h = Builder.new()
      |> Builder.add_ipvlan("ipv", parent: {:device, "eth0"}, subnet: {10, 0, 0, 0, 24})

      assert :ok = Builder.validate!(h, [], [])
    end
  end

  describe "to_term/1" do
    test "ipvlan mode emits network discriminated union" do
      h = Builder.new()
      |> Builder.add_ipvlan("edge", parent: {:device, "eth0"}, subnet: {10, 20, 0, 0, 24})

      term = Builder.to_term(h)
      assert %{network: %{mode: :ipvlan, parent: "eth0", parent_type: :device}} = term
      assert term.network.subnet == {10, 20, 0, 0}
      assert term.network.ipvlan_mode == :l3s
    end

    test "ipvlan with gateway emits gateway in network" do
      h = Builder.new()
      |> Builder.add_ipvlan("edge", parent: {:device, "eth0"}, subnet: {10, 20, 0, 0, 24},
                            gateway: {10, 20, 0, 1})

      term = Builder.to_term(h)
      assert term.network.gateway == {10, 20, 0, 1}
    end

    test "ipvlan without gateway emits nil gateway" do
      h = Builder.new()
      |> Builder.add_ipvlan("edge", parent: {:device, "eth0"}, subnet: {10, 20, 0, 0, 24})

      term = Builder.to_term(h)
      assert term.network.gateway == nil
    end

    test "empty host emits no network key" do
      term = Builder.new() |> Builder.to_term()
      refute Map.has_key?(term, :network)
    end
  end
end
