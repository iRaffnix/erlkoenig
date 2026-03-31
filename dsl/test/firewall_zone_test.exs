defmodule ErlkoenigNft.FirewallZoneTest do
  use ExUnit.Case, async: true

  alias ErlkoenigNft.Firewall.Builder

  # --- Zone DSL compilation tests ---

  defmodule RouterFirewall do
    use ErlkoenigNft.Firewall

    firewall "router" do
      counters [:ssh, :dropped]

      zone "wan", interfaces: ["eth0"]
      zone "lan", interfaces: ["eth1", "br0"]
      zone "vpn", interfaces: ["wg0"]

      zone_input "wan", policy: :drop do
        accept :established
        accept :icmp
        accept_tcp 22, counter: :ssh, limit: {10, burst: 3}
        log_and_drop "WAN-DROP: ", counter: :dropped
      end

      zone_input "lan", policy: :accept do
        accept :established
      end

      zone_forward "lan", to: "wan", policy: :accept do
        accept :established
        accept :all
      end

      zone_forward "wan", to: "lan", policy: :drop do
        accept :established
      end

      zone_masquerade "lan", to: "wan"

      chain "prerouting_ban", hook: :prerouting, priority: -300, policy: :accept do
        drop_if_in_set "blocklist"
      end
    end
  end

  defmodule MinimalZoneFirewall do
    use ErlkoenigNft.Firewall

    firewall "minimal_zone" do
      zone "ext", interfaces: ["eth0"]

      zone_input "ext", policy: :drop do
        accept :established
      end
    end
  end

  defmodule InterfaceMacroFirewall do
    use ErlkoenigNft.Firewall

    firewall "ifmacro" do
      chain "forward", hook: :forward, type: :filter, policy: :drop do
        accept_forward_established()
        accept_on_interface "wg0"
        accept_output_interface "eth0"
      end

      chain "masq", hook: :postrouting, type: :nat, policy: :accept do
        masquerade()
        masquerade_not_via "wg0"
      end
    end
  end

  describe "Zone DSL compilation" do
    test "RouterFirewall generates zone dispatch chains" do
      term = RouterFirewall.config()
      chain_names = Enum.map(term.chains, & &1.name)

      assert "z_dispatch_input" in chain_names
      assert "z_input_wan" in chain_names
      assert "z_input_lan" in chain_names
      # vpn has no zone_input → no z_input_vpn chain, just iifname_accept in dispatch
      refute "z_input_vpn" in chain_names
      assert "z_dispatch_forward" in chain_names
      assert "z_fwd_lan_wan" in chain_names
      assert "z_fwd_wan_lan" in chain_names
      assert "z_nat_postrouting" in chain_names
      # Manual chain preserved
      assert "prerouting_ban" in chain_names
    end

    test "z_dispatch_input has ct_established, loopback, and iifname_jump rules" do
      term = RouterFirewall.config()
      dispatch = Enum.find(term.chains, &(&1.name == "z_dispatch_input"))

      assert dispatch.hook == :input
      assert dispatch.policy == :drop

      rules = dispatch.rules
      assert hd(rules) == :ct_established_accept
      assert Enum.at(rules, 1) == {:iifname_accept, "lo"}
      # WAN zone: eth0 -> z_input_wan
      assert {:iifname_jump, "eth0", "z_input_wan"} in rules
      # LAN zone: eth1, br0 -> z_input_lan
      assert {:iifname_jump, "eth1", "z_input_lan"} in rules
      assert {:iifname_jump, "br0", "z_input_lan"} in rules
      # VPN zone has no zone_input → implicitly accepted
      assert {:iifname_accept, "wg0"} in rules
    end

    test "z_input_wan is a regular chain with user rules" do
      term = RouterFirewall.config()
      chain = Enum.find(term.chains, &(&1.name == "z_input_wan"))

      # Regular chain — no hook key
      refute Map.has_key?(chain, :hook)
      assert :ct_established_accept in chain.rules
      assert :icmp_accept in chain.rules
      # policy: drop → no implicit accept
      refute :accept in chain.rules
    end

    test "z_input_lan has implicit accept (policy: :accept)" do
      term = RouterFirewall.config()
      chain = Enum.find(term.chains, &(&1.name == "z_input_lan"))

      refute Map.has_key?(chain, :hook)
      assert List.last(chain.rules) == :accept
    end

    test "z_dispatch_forward has iifname_oifname_jump rules" do
      term = RouterFirewall.config()
      dispatch = Enum.find(term.chains, &(&1.name == "z_dispatch_forward"))

      assert dispatch.hook == :forward
      assert dispatch.policy == :drop

      # LAN (eth1, br0) -> WAN (eth0)
      assert {:iifname_oifname_jump, "eth1", "eth0", "z_fwd_lan_wan"} in dispatch.rules
      assert {:iifname_oifname_jump, "br0", "eth0", "z_fwd_lan_wan"} in dispatch.rules
      # WAN (eth0) -> LAN (eth1, br0)
      assert {:iifname_oifname_jump, "eth0", "eth1", "z_fwd_wan_lan"} in dispatch.rules
      assert {:iifname_oifname_jump, "eth0", "br0", "z_fwd_wan_lan"} in dispatch.rules
    end

    test "z_fwd_lan_wan has accept (policy: :accept)" do
      term = RouterFirewall.config()
      chain = Enum.find(term.chains, &(&1.name == "z_fwd_lan_wan"))

      refute Map.has_key?(chain, :hook)
      assert List.last(chain.rules) == :accept
    end

    test "z_fwd_wan_lan has no implicit accept (policy: :drop)" do
      term = RouterFirewall.config()
      chain = Enum.find(term.chains, &(&1.name == "z_fwd_wan_lan"))

      refute :accept in chain.rules
    end

    test "z_nat_postrouting has iifname_oifname_masq rules" do
      term = RouterFirewall.config()
      chain = Enum.find(term.chains, &(&1.name == "z_nat_postrouting"))

      assert chain.hook == :postrouting
      assert chain.type == :nat
      assert chain.priority == 100
      assert chain.policy == :accept

      # LAN (eth1, br0) -> WAN (eth0)
      assert {:iifname_oifname_masq, "eth1", "eth0"} in chain.rules
      assert {:iifname_oifname_masq, "br0", "eth0"} in chain.rules
    end

    test "zone chains come before manual chains" do
      term = RouterFirewall.config()
      chain_names = Enum.map(term.chains, & &1.name)
      ban_idx = Enum.find_index(chain_names, &(&1 == "prerouting_ban"))
      dispatch_idx = Enum.find_index(chain_names, &(&1 == "z_dispatch_input"))
      assert dispatch_idx < ban_idx
    end

    test "minimal zone firewall with single zone" do
      term = MinimalZoneFirewall.config()
      chain_names = Enum.map(term.chains, & &1.name)

      assert "z_dispatch_input" in chain_names
      assert "z_input_ext" in chain_names
      # No forwards → no forward dispatch
      refute "z_dispatch_forward" in chain_names
      # No masquerades → no NAT chain
      refute "z_nat_postrouting" in chain_names
    end

    test "zone without zone_input is implicitly trusted (iifname_accept)" do
      b = Builder.new("t")
      b = Builder.add_zone(b, "wan", interfaces: ["eth0"])
      b = Builder.add_zone(b, "mgmt", interfaces: ["eth2"])
      b = Builder.add_zone_input(b, "wan", :drop, [:ct_established_accept])
      # mgmt has no zone_input — should get iifname_accept in dispatch
      term = Builder.to_term(b)

      dispatch = Enum.find(term.chains, &(&1.name == "z_dispatch_input"))
      assert {:iifname_jump, "eth0", "z_input_wan"} in dispatch.rules
      assert {:iifname_accept, "eth2"} in dispatch.rules
      # No z_input_mgmt chain should exist
      refute Enum.any?(term.chains, &(&1.name == "z_input_mgmt"))
    end

    test "no zones produces no zone chains" do
      b = Builder.new("plain")
      b = Builder.add_chain(b, "in", [hook: :input, policy: :drop], [:ct_established_accept])
      term = Builder.to_term(b)
      assert length(term.chains) == 1
      assert hd(term.chains).name == "in"
    end
  end

  describe "Interface macros" do
    test "accept_forward_established produces :forward_established" do
      term = InterfaceMacroFirewall.config()
      fwd = Enum.find(term.chains, &(&1.name == "forward"))
      assert :forward_established in fwd.rules
    end

    test "accept_on_interface produces {:iifname_accept, name}" do
      term = InterfaceMacroFirewall.config()
      fwd = Enum.find(term.chains, &(&1.name == "forward"))
      assert {:iifname_accept, "wg0"} in fwd.rules
    end

    test "accept_output_interface produces {:oifname_accept, name}" do
      term = InterfaceMacroFirewall.config()
      fwd = Enum.find(term.chains, &(&1.name == "forward"))
      assert {:oifname_accept, "eth0"} in fwd.rules
    end

    test "masquerade produces :masq" do
      term = InterfaceMacroFirewall.config()
      masq = Enum.find(term.chains, &(&1.name == "masq"))
      assert :masq in masq.rules
    end

    test "masquerade_not_via produces {:oifname_neq_masq, name}" do
      term = InterfaceMacroFirewall.config()
      masq = Enum.find(term.chains, &(&1.name == "masq"))
      assert {:oifname_neq_masq, "wg0"} in masq.rules
    end
  end

  describe "Builder rule constructors" do
    test "new interface rule constructors" do
      assert Builder.oifname_accept("eth0") == {:oifname_accept, "eth0"}
      assert Builder.oifname_neq_masq("wg0") == {:oifname_neq_masq, "wg0"}
      assert Builder.masquerade() == :masq
      assert Builder.forward_established() == :forward_established
    end
  end

  describe "Zone validation" do
    test "duplicate zone names raise" do
      b = Builder.new("t")
      b = Builder.add_zone(b, "wan", interfaces: ["eth0"])
      b = Builder.add_zone(b, "wan", interfaces: ["eth1"])

      assert_raise RuntimeError, ~r/Duplicate zone names/, fn ->
        Builder.to_term(b)
      end
    end

    test "duplicate interface across zones raises" do
      b = Builder.new("t")
      b = Builder.add_zone(b, "wan", interfaces: ["eth0"])
      b = Builder.add_zone(b, "lan", interfaces: ["eth0"])

      assert_raise RuntimeError, ~r/Interface.*multiple zones/, fn ->
        Builder.to_term(b)
      end
    end

    test "zone_input referencing undefined zone raises" do
      b = Builder.new("t")
      b = Builder.add_zone(b, "wan", interfaces: ["eth0"])
      b = Builder.add_zone_input(b, "lan", :drop, [:ct_established_accept])

      assert_raise RuntimeError, ~r/undefined zone.*"lan"/, fn ->
        Builder.to_term(b)
      end
    end

    test "zone_forward referencing undefined zone raises" do
      b = Builder.new("t")
      b = Builder.add_zone(b, "wan", interfaces: ["eth0"])
      b = Builder.add_zone_forward(b, "wan", "dmz", :drop, [])

      assert_raise RuntimeError, ~r/undefined zone.*"dmz"/, fn ->
        Builder.to_term(b)
      end
    end

    test "zone_masquerade referencing undefined zone raises" do
      b = Builder.new("t")
      b = Builder.add_zone(b, "wan", interfaces: ["eth0"])
      b = Builder.add_zone_masquerade(b, "lan", "wan")

      assert_raise RuntimeError, ~r/undefined zone.*"lan"/, fn ->
        Builder.to_term(b)
      end
    end
  end

  describe "write! with zones" do
    test "zone config produces valid term file" do
      path = Path.join(System.tmp_dir!(), "nft_zone_test_#{:rand.uniform(100000)}.term")
      RouterFirewall.write!(path)
      content = File.read!(path)
      assert content =~ "z_dispatch_input"
      assert content =~ "z_input_wan"
      assert content =~ "z_fwd_lan_wan"
      assert content =~ "z_nat_postrouting"
      File.rm!(path)
    end
  end
end
