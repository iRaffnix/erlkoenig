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

  # ═══════════════════════════════════════════════════════
  # Advanced actions (docs verification)
  # ═══════════════════════════════════════════════════════

  test "reject action compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Reject do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
            nft_rule :reject
          end
        end
      end
    end
    """)
    {action, _} = hd(hd(hd(mod.config().nft_tables).chains).rules)
    assert action == :reject
  end

  test "notrack action compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Notrack do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          base_chain "prerouting", hook: :prerouting, type: :filter, priority: :raw, policy: :accept do
            nft_rule :notrack, tcp_dport: 8080
          end
        end
      end
    end
    """)
    {action, opts} = hd(hd(hd(mod.config().nft_tables).chains).rules)
    assert action == :notrack
    assert opts.tcp_dport == 8080
  end

  test "ct_mark_set and ct_mark_match compile" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.CtMark do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          base_chain "forward", hook: :forward, type: :filter, priority: :filter, policy: :drop do
            nft_rule :ct_mark_set, iifname: "eth0", mark: 1
            nft_rule :ct_mark_match, mark: 1
          end
        end
      end
    end
    """)
    rules = hd(hd(mod.config().nft_tables).chains).rules
    {a1, o1} = Enum.at(rules, 0)
    assert a1 == :ct_mark_set
    assert o1.mark == 1
    {a2, o2} = Enum.at(rules, 1)
    assert a2 == :ct_mark_match
    assert o2.mark == 1
  end

  test "snat action compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Snat do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          base_chain "postrouting", hook: :postrouting, type: :nat, priority: :srcnat, policy: :accept do
            nft_rule :snat, ip_saddr: {10, 0, 0, 0, 24}, snat_to: {192, 168, 1, 1}
          end
        end
      end
    end
    """)
    {action, opts} = hd(hd(hd(mod.config().nft_tables).chains).rules)
    assert action == :snat
    assert opts.snat_to == {192, 168, 1, 1}
  end

  test "dnat action compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Dnat do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          base_chain "prerouting", hook: :prerouting, type: :nat, priority: :dstnat, policy: :accept do
            nft_rule :dnat, tcp_dport: 8080, dnat_to: {10, 0, 0, 2, 8080}
          end
        end
      end
    end
    """)
    {action, opts} = hd(hd(hd(mod.config().nft_tables).chains).rules)
    assert action == :dnat
    assert opts.dnat_to == {10, 0, 0, 2, 8080}
    assert opts.tcp_dport == 8080
  end

  test "fib_rpf action compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.FibRpf do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          base_chain "prerouting", hook: :prerouting, type: :filter, priority: :filter, policy: :accept do
            nft_rule :fib_rpf
          end
        end
      end
    end
    """)
    {action, _} = hd(hd(hd(mod.config().nft_tables).chains).rules)
    assert action == :fib_rpf
  end

  test "connlimit_drop action compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Connlimit do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
            nft_rule :connlimit_drop, tcp_dport: 80, limit: 100
          end
        end
      end
    end
    """)
    {action, opts} = hd(hd(hd(mod.config().nft_tables).chains).rules)
    assert action == :connlimit_drop
    assert opts.limit == 100
    assert opts.tcp_dport == 80
  end

  test "nft_set compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Set do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          nft_set "blocklist", :ipv4_addr

          base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
            nft_rule :drop, set: "blocklist"
          end
        end
      end
    end
    """)
    table = hd(mod.config().nft_tables)
    assert table.sets == [{"blocklist", :ipv4_addr}]
    {_, opts} = hd(hd(table.chains).rules)
    assert opts.set == "blocklist"
  end

  test "nft_vmap compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.Vmap do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          nft_vmap "dispatch", :ipv4_addr, [
            {{10, 0, 0, 2}, {:jump, "handle-web"}},
            {{10, 0, 0, 3}, {:jump, "handle-api"}}
          ]

          nft_chain "handle-web" do
            nft_rule :accept
          end

          nft_chain "handle-api" do
            nft_rule :accept
          end

          base_chain "forward", hook: :forward, type: :filter, priority: :filter, policy: :drop do
            nft_rule :vmap_dispatch, vmap: "dispatch"
          end
        end
      end
    end
    """)
    table = hd(mod.config().nft_tables)
    assert length(table.vmaps) == 1
    vmap = hd(table.vmaps)
    assert vmap.name == "dispatch"
    assert vmap.type == :ipv4_addr
    assert length(vmap.entries) == 2
  end

  test "tcp_dport range compiles" do
    [{mod, _}] = Code.compile_string(~S"""
    defmodule TestNft.PortRange do
      use Erlkoenig.Stack
      host do
        nft_table :inet, "fw" do
          base_chain "input", hook: :input, type: :filter, priority: :filter, policy: :drop do
            nft_rule :accept, tcp_dport: {8000, 9000}
          end
        end
      end
    end
    """)
    {_, opts} = hd(hd(hd(mod.config().nft_tables).chains).rules)
    assert opts.tcp_dport == {8000, 9000}
  end

  # ═══════════════════════════════════════════════════════
  # Full examples (docs verification)
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
    assert length(host_table.chains) == 2  # input + prerouting (raw ban)

    # erlkoenig table
    ek_table = Enum.find(config.nft_tables, & &1.name == "erlkoenig")
    assert length(ek_table.counters) == 4
    assert length(ek_table.chains) == 6  # prerouting_nat + 3 egress + forward + postrouting

    # forward chain has egress vmap lookup + fwd policy vmap lookup
    fwd = Enum.find(ek_table.chains, & &1.name == "forward")
    vmap_lookups = Enum.filter(fwd.rules, fn {action, _} -> action == :vmap_lookup end)
    assert length(vmap_lookups) == 2

    # egress dispatch is ifname vmap
    assert length(ek_table.vmaps) == 2
    egress = Enum.find(ek_table.vmaps, & &1.name == "egress_dispatch")
    assert egress.type == :ifname
  end
end
