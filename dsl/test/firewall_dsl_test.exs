defmodule Erlkoenig.FirewallDslTest do
  use ExUnit.Case, async: true

  # --- DSL macro tests ---
  # Each test module uses the DSL macros and verifies the compiled output.

  defmodule WebFirewall do
    use Erlkoenig.Firewall

    firewall "web" do
      counters [:ssh, :dropped]
      set "blocklist", :ipv4_addr, timeout: 3600

      chain "inbound", hook: :input, policy: :drop do
        accept :established
        accept :icmp
        accept_tcp 22, counter: :ssh, limit: {5, burst: 2}
        accept_tcp [80, 443]
        drop_if_in_set "blocklist", counter: :dropped
        log_and_drop "BLOCKED: "
      end
    end
  end

  defmodule MinimalFirewall do
    use Erlkoenig.Firewall

    firewall "minimal" do
      chain "inbound", hook: :input, policy: :drop do
        accept :established
        accept :loopback
      end
    end
  end

  defmodule WorkerFirewall do
    use Erlkoenig.Firewall

    firewall "worker" do
      chain "inbound", hook: :input, policy: :drop do
        accept :established
        accept :icmp
        accept_udp 53
        accept :all
      end
    end
  end

  describe "DSL compilation" do
    test "WebFirewall compiles with all features" do
      term = WebFirewall.config()
      assert is_map(term)
      assert length(term.chains) == 1
      assert term.counters == ["ssh", "dropped"]
      assert length(term.sets) == 1
    end

    test "WebFirewall chain has correct rules" do
      term = WebFirewall.config()
      [chain] = term.chains
      assert chain.name == "inbound"
      assert chain.hook == :input
      assert chain.policy == :drop

      rules = chain.rules
      assert hd(rules) == :ct_established_accept
      assert Enum.at(rules, 1) == :icmp_accept
      assert {:tcp_accept_limited, 22, "ssh", %{rate: 5, burst: 2}} in rules
      assert {:tcp_accept, 80} in rules
      assert {:tcp_accept, 443} in rules
    end

    test "WebFirewall has set with timeout" do
      term = WebFirewall.config()
      [set] = term.sets
      assert elem(set, 0) == "blocklist"
      assert elem(set, 1) == :ipv4_addr
    end

    test "MinimalFirewall has only established + loopback" do
      term = MinimalFirewall.config()
      [chain] = term.chains
      assert chain.rules == [:ct_established_accept, {:iifname_accept, "lo"}]
    end

    test "WorkerFirewall matches old hardcoded default" do
      term = WorkerFirewall.config()
      [chain] = term.chains

      assert chain.rules == [
               :ct_established_accept,
               :icmp_accept,
               {:udp_accept, 53},
               :accept
             ]
    end

    test "write! produces file" do
      path = Path.join(System.tmp_dir!(), "erlkoenig_dsl_test_#{:rand.uniform(100000)}.term")
      WebFirewall.write!(path)
      assert File.exists?(path)
      content = File.read!(path)
      assert content =~ "inbound"
      File.rm!(path)
    end
  end
end
