defmodule NftDslTest do
  use ExUnit.Case

  # ═══════════════════════════════════════════════════════
  # nft_table basics
  # ═══════════════════════════════════════════════════════

  test "nft_table with base_chain compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Basic do
      use Erlkoenig.Stack

      host do
        nft_table :inet, "test" do
          base_chain "input",
            hook: :input, type: :filter,
            priority: :filter, policy: :drop do

            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, iifname: "lo"
            nft_rule :accept, tcp_dport: 22
            nft_rule :drop
          end
        end
      end
    end
    """)

    config = mod.config()
    assert length(config.nft_tables) == 1

    table = hd(config.nft_tables)
    assert table.family == :inet
    assert table.name == "test"
    assert length(table.chains) == 1

    chain = hd(table.chains)
    assert chain.hook == :input
    assert chain.type == :filter
    assert chain.priority == :filter
    assert chain.policy == :drop
    assert length(chain.rules) == 4
  end

  test "nft_table with regular chain (no hook)" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.RegularChain do
      use Erlkoenig.Stack

      host do
        nft_table :inet, "fw" do
          nft_chain "my-chain" do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, tcp_dport: 8080
            nft_rule :drop
          end
        end
      end
    end
    """)

    chain = hd(hd(mod.config().nft_tables).chains)
    assert chain.name == "my-chain"
    refute Map.has_key?(chain, :hook)
    refute Map.has_key?(chain, :policy)
    assert length(chain.rules) == 3
  end

  # ═══════════════════════════════════════════════════════
  # Counters
  # ═══════════════════════════════════════════════════════

  test "nft_counter declared and referenced" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Counter do
      use Erlkoenig.Stack

      host do
        nft_table :inet, "fw" do
          nft_counter "my_drops"

          base_chain "forward",
            hook: :forward, type: :filter,
            priority: :filter, policy: :drop do

            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :drop, counter: "my_drops"
          end
        end
      end
    end
    """)

    table = hd(mod.config().nft_tables)
    assert table.counters == ["my_drops"]

    chain = hd(table.chains)
    {_action, opts} = List.last(chain.rules)
    assert opts.counter == "my_drops"
  end

  test "counter reference to undeclared counter raises" do
    assert_raise CompileError, ~r/counter.*"missing".*not declared/, fn ->
      Code.compile_string(~S"""
      defmodule TestNft.BadCounter do
        use Erlkoenig.Stack

        host do
          nft_table :inet, "fw" do
            base_chain "forward",
              hook: :forward, type: :filter,
              priority: :filter, policy: :drop do

              nft_rule :drop, counter: "missing"
            end
          end
        end
      end
      """)
    end
  end

  # ═══════════════════════════════════════════════════════
  # Rule actions
  # ═══════════════════════════════════════════════════════

  test "all rule actions compile" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Actions do
      use Erlkoenig.Stack

      host do
        nft_table :inet, "fw" do
          nft_chain "target" do
            nft_rule :accept, tcp_dport: 80
          end

          base_chain "forward",
            hook: :forward, type: :filter,
            priority: :filter, policy: :drop do

            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :jump, iifname: "eth0", to: "target"
            nft_rule :return
            nft_rule :drop, log_prefix: "DROP: "
          end

          base_chain "postrouting",
            hook: :postrouting, type: :nat,
            priority: :srcnat, policy: :accept do

            nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "br0"
          end
        end
      end
    end
    """)

    config = mod.config()
    table = hd(config.nft_tables)
    assert length(table.chains) == 3

    fwd = Enum.find(table.chains, & &1.name == "forward")
    actions = Enum.map(fwd.rules, fn {action, _} -> action end)
    assert actions == [:accept, :jump, :return, :drop]

    post = Enum.find(table.chains, & &1.name == "postrouting")
    [{:masquerade, opts}] = post.rules
    assert opts.ip_saddr == {10, 0, 0, 0, 24}
    assert opts.oifname_ne == "br0"
  end

  test "jump without :to raises" do
    assert_raise CompileError, ~r/jump requires :to/, fn ->
      Code.compile_string(~S"""
      defmodule TestNft.BadJump do
        use Erlkoenig.Stack

        host do
          nft_table :inet, "fw" do
            base_chain "forward",
              hook: :forward, type: :filter,
              priority: :filter, policy: :drop do

              nft_rule :jump, iifname: "eth0"
            end
          end
        end
      end
      """)
    end
  end

  test "invalid action raises" do
    assert_raise CompileError, ~r/invalid action/, fn ->
      Code.compile_string(~S"""
      defmodule TestNft.BadAction do
        use Erlkoenig.Stack

        host do
          nft_table :inet, "fw" do
            base_chain "input",
              hook: :input, type: :filter,
              priority: :filter, policy: :drop do

              nft_rule :explode
            end
          end
        end
      end
      """)
    end
  end

  # ═══════════════════════════════════════════════════════
  # Match fields
  # ═══════════════════════════════════════════════════════

  test "all match fields preserved in term" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.MatchFields do
      use Erlkoenig.Stack

      host do
        bridge "br0", subnet: {10, 0, 0, 0, 24}

        nft_table :inet, "fw" do
          base_chain "forward",
            hook: :forward, type: :filter,
            priority: :filter, policy: :drop do

            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, iifname: "eth0", tcp_dport: 443
            nft_rule :accept, oifname: "br0", udp_dport: 53
            nft_rule :accept, ip_saddr: {10, 0, 0, 0, 24}, ip_daddr: {192, 168, 1, 1, 32}
            nft_rule :accept, iifname: "br0", oifname_ne: "eth0"
            nft_rule :drop, log_prefix: "FWD: "
          end
        end
      end

      pod "web" do
        container "app", binary: "/opt/app"
      end

      attach "web", to: "br0", replicas: 1
    end
    """)

    chain = hd(hd(mod.config().nft_tables).chains)
    rules = chain.rules

    # ct_state
    {_, opts0} = Enum.at(rules, 0)
    assert opts0.ct_state == [:established, :related]

    # iifname + tcp_dport
    {_, opts1} = Enum.at(rules, 1)
    assert opts1.iifname == "eth0"
    assert opts1.tcp_dport == 443

    # oifname + udp_dport
    {_, opts2} = Enum.at(rules, 2)
    assert opts2.oifname == "br0"
    assert opts2.udp_dport == 53

    # ip_saddr + ip_daddr
    {_, opts3} = Enum.at(rules, 3)
    assert opts3.ip_saddr == {10, 0, 0, 0, 24}
    assert opts3.ip_daddr == {192, 168, 1, 1, 32}

    # oifname_ne
    {_, opts4} = Enum.at(rules, 4)
    assert opts4.oifname_ne == "eth0"

    # log_prefix
    {_, opts5} = Enum.at(rules, 5)
    assert opts5.log_prefix == "FWD: "
  end

  # ═══════════════════════════════════════════════════════
  # Compile-time expansions (symbols preserved in .term)
  # ═══════════════════════════════════════════════════════

  test "veth_of and replica_ips preserved as symbols" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Symbols do
      use Erlkoenig.Stack

      host do
        bridge "br0", subnet: {10, 0, 0, 0, 24}

        nft_table :inet, "fw" do
          base_chain "forward",
            hook: :forward, type: :filter,
            priority: :filter, policy: :drop do

            nft_rule :jump, iifname: {:veth_of, "web", "nginx"}, to: "from-web"
            nft_rule :accept, ip_daddr: {:replica_ips, "web", "nginx"}, tcp_dport: 8080
            nft_rule :accept,
              ip_saddr: {:replica_ips, "web", "nginx"},
              ip_daddr: {:replica_ips, "app", "api"},
              tcp_dport: 4000
          end
        end
      end

      pod "web" do
        container "nginx", binary: "/opt/nginx"
      end

      pod "app" do
        container "api", binary: "/opt/api"
      end

      attach "web", to: "br0", replicas: 3
      attach "app", to: "br0", replicas: 1
    end
    """)

    chain = hd(hd(mod.config().nft_tables).chains)

    # jump with veth_of
    {action0, opts0} = Enum.at(chain.rules, 0)
    assert action0 == :jump
    assert opts0.iifname == {:veth_of, "web", "nginx"}
    assert opts0.to == "from-web"

    # replica_ips in daddr
    {_, opts1} = Enum.at(chain.rules, 1)
    assert opts1.ip_daddr == {:replica_ips, "web", "nginx"}

    # replica_ips in both saddr and daddr
    {_, opts2} = Enum.at(chain.rules, 2)
    assert opts2.ip_saddr == {:replica_ips, "web", "nginx"}
    assert opts2.ip_daddr == {:replica_ips, "app", "api"}
  end

  # ═══════════════════════════════════════════════════════
  # Validation errors
  # ═══════════════════════════════════════════════════════

  test "duplicate table names raise" do
    assert_raise CompileError, ~r/duplicate nft_table/, fn ->
      Code.compile_string(~S"""
      defmodule TestNft.DupTable do
        use Erlkoenig.Stack

        host do
          nft_table :inet, "same" do
            base_chain "a", hook: :input, type: :filter, priority: :filter, policy: :drop do
              nft_rule :drop
            end
          end

          nft_table :inet, "same" do
            base_chain "b", hook: :forward, type: :filter, priority: :filter, policy: :drop do
              nft_rule :drop
            end
          end
        end
      end
      """)
    end
  end

  test "duplicate chain names in table raise" do
    assert_raise CompileError, ~r/duplicate chain/, fn ->
      Code.compile_string(~S"""
      defmodule TestNft.DupChain do
        use Erlkoenig.Stack

        host do
          nft_table :inet, "fw" do
            nft_chain "same" do
              nft_rule :drop
            end

            nft_chain "same" do
              nft_rule :accept
            end
          end
        end
      end
      """)
    end
  end

  test "empty table raises" do
    assert_raise CompileError, ~r/at least one chain/, fn ->
      Code.compile_string(~S"""
      defmodule TestNft.EmptyTable do
        use Erlkoenig.Stack

        host do
          nft_table :inet, "empty" do
          end
        end
      end
      """)
    end
  end

  test "base_chain missing hook raises" do
    assert_raise KeyError, fn ->
      Code.compile_string(~S"""
      defmodule TestNft.NoHook do
        use Erlkoenig.Stack

        host do
          nft_table :inet, "fw" do
            base_chain "bad", type: :filter, priority: :filter, policy: :drop do
              nft_rule :drop
            end
          end
        end
      end
      """)
    end
  end

  test "invalid hook raises" do
    assert_raise CompileError, ~r/invalid hook/, fn ->
      Code.compile_string(~S"""
      defmodule TestNft.BadHook do
        use Erlkoenig.Stack

        host do
          nft_table :inet, "fw" do
            base_chain "bad", hook: :banana, type: :filter, priority: :filter, policy: :drop do
              nft_rule :drop
            end
          end
        end
      end
      """)
    end
  end

  # ═══════════════════════════════════════════════════════
  # Full three-tier example compiles
  # ═══════════════════════════════════════════════════════

  test "three_tier_nft example compiles" do
    [{mod, _}] = Code.compile_file("../examples/three_tier_nft.exs")

    config = mod.config()
    assert length(config.nft_tables) == 2
    assert length(config.pods) == 3
    assert length(config.zones) == 3

    # host table
    host_table = Enum.find(config.nft_tables, & &1.name == "host")
    assert host_table.family == :inet
    assert length(host_table.chains) == 1

    # erlkoenig table
    ek_table = Enum.find(config.nft_tables, & &1.name == "erlkoenig")
    assert length(ek_table.counters) == 4
    assert length(ek_table.chains) == 5  # forward + 3 egress + postrouting

    # forward chain has jump rules
    fwd = Enum.find(ek_table.chains, & &1.name == "forward")
    jumps = Enum.filter(fwd.rules, fn {action, _} -> action == :jump end)
    assert length(jumps) == 3
  end
end
