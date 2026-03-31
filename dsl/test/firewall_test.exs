defmodule ErlkoenigNft.FirewallTest do
  use ExUnit.Case, async: true

  alias ErlkoenigNft.Firewall.Builder
  alias ErlkoenigNft.Firewall.Profiles

  # --- Builder tests ---

  describe "Builder" do
    test "new creates empty state" do
      b = Builder.new("test")
      assert b.name == "test"
      assert b.chains == []
      assert b.sets == []
      assert b.counters == []
    end

    test "add_chain builds chain with rules" do
      b = Builder.new("t")

      b =
        Builder.add_chain(b, "input", [hook: :input, policy: :drop], [
          :ct_established_accept,
          {:tcp_accept, 80}
        ])

      term = Builder.to_term(b)
      assert length(term.chains) == 1
      [chain] = term.chains
      assert chain.name == "input"
      assert chain.hook == :input
      assert chain.policy == :drop
      assert chain.rules == [:ct_established_accept, {:tcp_accept, 80}]
    end

    test "add_set without timeout" do
      b = Builder.new("t") |> Builder.add_set("blocklist", :ipv4_addr)
      term = Builder.to_term(b)
      assert term.sets == [{"blocklist", :ipv4_addr}]
    end

    test "add_set with timeout" do
      b = Builder.new("t") |> Builder.add_set("banlist", :ipv4_addr, timeout: 3600)
      term = Builder.to_term(b)
      [{name, type, opts}] = term.sets
      assert name == "banlist"
      assert type == :ipv4_addr
      assert opts.timeout == 3600
    end

    test "add_counters" do
      b = Builder.new("t") |> Builder.add_counters([:ssh, :dropped])
      term = Builder.to_term(b)
      assert term.counters == ["ssh", "dropped"]
    end

    test "rule constructors return correct tuples" do
      assert Builder.ct_established_accept() == :ct_established_accept
      assert Builder.icmp_accept() == :icmp_accept
      assert Builder.accept() == :accept
      assert Builder.tcp_accept(80) == {:tcp_accept, 80}
      assert Builder.tcp_reject(25) == {:tcp_reject, 25}
      assert Builder.udp_accept(53) == {:udp_accept, 53}
      assert Builder.log_drop("X: ") == {:log_drop, "X: "}
      assert Builder.log_reject("R: ") == {:log_reject, "R: "}
      assert Builder.set_lookup_drop("bl") == {:set_lookup_drop, "bl"}
      assert Builder.connlimit_drop(100) == {:connlimit_drop, 100, 1}
      assert Builder.dnat({10, 0, 0, 1}, 80) == {:dnat, {10, 0, 0, 1}, 80}
      assert Builder.nflog_capture_udp(61820, "LOG:", 0) == {:nflog_capture_udp, 61820, "LOG:", 0}
      assert Builder.set_lookup_udp_accept("allowlist", 51820) == {:set_lookup_udp_accept, "allowlist", 51820}
      assert Builder.log_drop_nflog("DROP: ", 0, :dropped) == {:log_drop_nflog, "DROP: ", 0, "dropped"}
    end

    test "tcp_accept with counter" do
      assert Builder.tcp_accept(22, counter: :ssh) == {:tcp_accept, 22, "ssh"}
    end

    test "tcp_accept with limit" do
      result = Builder.tcp_accept(22, counter: :ssh, limit: {5, burst: 2})
      assert result == {:tcp_accept_limited, 22, "ssh", %{rate: 5, burst: 2}}
    end

    test "push_rule and take_rules" do
      b = Builder.new("t")
      b = Builder.push_rule(b, :ct_established_accept)
      b = Builder.push_rule(b, {:tcp_accept, 80})
      {rules, b} = Builder.take_rules(b)
      assert rules == [:ct_established_accept, {:tcp_accept, 80}]
      assert b.rules_acc == []
    end

    test "to_term omits empty sets and counters" do
      b = Builder.new("t")
      b = Builder.add_chain(b, "in", [hook: :input, policy: :drop], [:accept])
      term = Builder.to_term(b)
      assert term.table == "t"
      refute Map.has_key?(term, :sets)
      refute Map.has_key?(term, :counters)
    end

    test "write! creates readable term file" do
      path = Path.join(System.tmp_dir!(), "nft_dsl_test_#{:rand.uniform(100000)}.term")

      b = Builder.new("t")
      b = Builder.add_chain(b, "in", [hook: :input, policy: :drop], [:ct_established_accept])
      Builder.write!(b, path)

      content = File.read!(path)
      assert content =~ "chains"
      assert content =~ "ct_established_accept"

      File.rm!(path)
    end
  end

  # --- Profile tests ---

  describe "Profiles" do
    test ":strict has no outbound accept" do
      term = Profiles.get(:strict)
      [chain] = term.chains
      assert chain.policy == :drop
      refute :accept in chain.rules
    end

    test ":strict with allow_tcp adds tcp rules" do
      term = Profiles.get(:strict, allow_tcp: [443, 80])
      [chain] = term.chains
      assert {:tcp_accept, 443} in chain.rules
      assert {:tcp_accept, 80} in chain.rules
    end

    test ":standard has DNS and outbound accept" do
      term = Profiles.get(:standard)
      [chain] = term.chains
      assert {:udp_accept, 53} in chain.rules
      assert :accept in chain.rules
    end

    test ":open has accept policy" do
      term = Profiles.get(:open)
      [chain] = term.chains
      assert chain.policy == :accept
    end

    test "list returns all profiles" do
      assert Profiles.list() == [:strict, :standard, :open]
    end
  end
end
