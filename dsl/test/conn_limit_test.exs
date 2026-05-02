defmodule Erlkoenig.ConnLimitTest do
  use ExUnit.Case, async: true

  # SPEC-EK-028 phase 1 — `conn_limit per_ip: N` is chain-scoped
  # sugar that expands to a visible `{:connlimit_drop, %{max: N}}`
  # rule at the location the operator wrote it. No auto-synthesis,
  # no hidden chain creation. These tests pin that contract from
  # both ends of the DSL (table-level and container-inline).

  alias Erlkoenig.Nft.ChainBuilder

  # ============================================================
  # Low-level: compile_conn_limit!/1 shared validator
  # ============================================================

  describe "compile_conn_limit!/1" do
    test "per_ip: positive integer → {:connlimit_drop, max: N}" do
      assert {:connlimit_drop, [max: 100]} =
               ChainBuilder.compile_conn_limit!(per_ip: 100)
    end

    test "missing per_ip raises" do
      assert_raise CompileError, ~r/needs :per_ip/, fn ->
        ChainBuilder.compile_conn_limit!([])
      end
    end

    test "zero per_ip raises" do
      assert_raise CompileError, ~r/positive integer/, fn ->
        ChainBuilder.compile_conn_limit!(per_ip: 0)
      end
    end

    test "negative per_ip raises" do
      assert_raise CompileError, ~r/positive integer/, fn ->
        ChainBuilder.compile_conn_limit!(per_ip: -5)
      end
    end

    test "non-integer per_ip raises" do
      assert_raise CompileError, ~r/positive integer/, fn ->
        ChainBuilder.compile_conn_limit!(per_ip: "100")
      end
    end

    test "removed option `global:` fails loud with migration hint" do
      assert_raise CompileError, ~r/option removed/, fn ->
        ChainBuilder.compile_conn_limit!(global: 5000)
      end
    end

    test "removed option `audit:` fails loud with migration hint" do
      assert_raise CompileError, ~r/option removed/, fn ->
        ChainBuilder.compile_conn_limit!(per_ip: 100, audit: :off)
      end
    end
  end

  # ============================================================
  # Chain-builder integration: conn_limit appears in chain.rules
  # ============================================================

  describe "ChainBuilder.add_conn_limit/2" do
    test "emits a connlimit_drop rule in the chain's rule list" do
      chain =
        ChainBuilder.new_base(
          "input",
          hook: :input,
          type: :filter,
          priority: 0,
          policy: :drop
        )
        |> ChainBuilder.add_conn_limit(per_ip: 100)

      assert chain.rules == [{:connlimit_drop, %{max: 100}}]
    end

    test "conn_limit preserves ordering with hand-written nft_rules" do
      chain =
        ChainBuilder.new_base(
          "input",
          hook: :input,
          type: :filter,
          priority: 0,
          policy: :drop
        )
        |> ChainBuilder.add_rule(:accept, ct_state: [:established])
        |> ChainBuilder.add_conn_limit(per_ip: 50)
        |> ChainBuilder.add_rule(:accept, tcp_dport: 8080)

      assert chain.rules == [
               {:accept, %{ct_state: [:established]}},
               {:connlimit_drop, %{max: 50}},
               {:accept, %{tcp_dport: 8080}}
             ]
    end
  end

  # ============================================================
  # Full Stack DSL — table-level base_chain form
  # ============================================================

  defmodule StackTableForm do
    use Erlkoenig.Stack

    host do
      ipvlan "demo", parent: {:dummy, "ek_demo"}, subnet: {10, 70, 0, 0, 24}

      nft_host do
        base_chain "input",
          hook: :input,
          type: :filter,
          priority: :filter,
          policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          conn_limit per_ip: 100
        end
      end
    end
  end

  test "table-level base_chain: conn_limit is visible in chain rules" do
    term = StackTableForm.config()
    [table] = term.nft_tables
    [chain] = table.chains

    # {action, opts_map} tuples — conn_limit is literally one of them
    assert Enum.member?(chain.rules, {:connlimit_drop, %{max: 100}})
  end

  # ============================================================
  # Full Stack DSL — container-inline `nft do input ... end end`
  # ============================================================

  defmodule StackContainerForm do
    use Erlkoenig.Stack

    host do
      ipvlan "demo", parent: {:dummy, "ek_demo"}, subnet: {10, 70, 0, 0, 24}
    end

    pod "api", strategy: :one_for_one do
      container "web",
        binary: "/opt/bin/web",
        zone: "demo",
        replicas: 1,
        restart: :permanent do
        nft do
          input policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            conn_limit per_ip: 200
            nft_rule :accept, tcp_dport: 8080
          end
        end
      end
    end
  end

  test "container-inline: conn_limit appears in the input chain's rules" do
    term = StackContainerForm.config()
    [pod] = term.pods
    [ct] = pod.containers
    [input_chain] = ct.nft.chains

    assert input_chain.rules == [
             {:accept, %{ct_state: [:established, :related]}},
             {:connlimit_drop, %{max: 200}},
             {:accept, %{tcp_dport: 8080}}
           ]
  end

  # ============================================================
  # Refusal: conn_limit at container level — no longer allowed
  # ============================================================

  test "conn_limit outside any chain context raises at compile time" do
    # Inside a container body but outside any `nft do ... end` block,
    # `conn_limit` compiles against an unbound `ek_nft_chain` variable
    # and the Elixir compiler surfaces a CompileError. Same failure
    # mode as `nft_rule` in the wrong context — intentional parity.
    #
    # Before the Glasbox fix this path silently synthesised a full
    # input chain in the kernel. The failure now is loud at DSL
    # compile time.
    assert_raise CompileError, fn ->
      defmodule RejectedContainerLevel do
        use Erlkoenig.Stack

        host do
          ipvlan "demo",
            parent: {:dummy, "ek_demo"},
            subnet: {10, 70, 0, 0, 24}
        end

        pod "api", strategy: :one_for_one do
          container "web",
            binary: "/opt/bin/web",
            zone: "demo",
            replicas: 1,
            restart: :permanent do
            conn_limit per_ip: 100
          end
        end
      end
    end
  end
end
