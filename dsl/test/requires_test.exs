defmodule Erlkoenig.RequiresTest do
  use ExUnit.Case, async: true

  alias Erlkoenig.Capabilities

  # ============================================================
  # Capabilities registry
  # ============================================================

  describe "Capabilities registry" do
    test "knows :journal.local" do
      assert {:ok, spec} = Capabilities.fetch(:"journal.local")
      assert spec.host_socket == "/run/erlkoenig/journal.sock"
      assert spec.container_socket == "/run/journal.sock"
      assert spec.env_var == "JOURNAL_LOCAL_SOCK"
    end

    test "rejects unknown names with the list of valid ones" do
      assert {:error, {:unknown_capability, :"nonsense.local", known}} =
               Capabilities.fetch(:"nonsense.local")

      assert :"journal.local" in known
    end

    test "fetch! raises with helpful message" do
      assert_raise ArgumentError, ~r/unknown capability :"nonsense.local"/, fn ->
        Capabilities.fetch!(:"nonsense.local")
      end
    end
  end

  # ============================================================
  # DSL: single capability
  # ============================================================

  defmodule WithJournal do
    use Erlkoenig.Container

    container :web do
      binary "/opt/bin/web"
      ip {10, 0, 0, 10}
      requires :"journal.local"
    end
  end

  describe "container with one requires" do
    setup do
      [%{name: "web"} = ct] = WithJournal.containers()
      {:ok, ct: ct}
    end

    test "records the capability in :requires", %{ct: ct} do
      assert ct.requires == [:"journal.local"]
    end

    test "injects the env var", %{ct: ct} do
      assert ct.env["JOURNAL_LOCAL_SOCK"] == "/run/journal.sock"
    end

    test "adds a socket bind-mount", %{ct: ct} do
      assert ct.socket_mounts == [
               %{host: "/run/erlkoenig/journal.sock",
                 container: "/run/journal.sock",
                 read_only: false}
             ]
    end

    test "preserves unrelated container fields", %{ct: ct} do
      assert ct.binary == "/opt/bin/web"
      assert ct.ip == {10, 0, 0, 10}
    end
  end

  # ============================================================
  # DSL: declaring the same capability twice is a no-op
  # ============================================================

  defmodule DuplicateRequires do
    use Erlkoenig.Container

    container :app do
      binary "/opt/bin/app"
      requires :"journal.local"
      requires :"journal.local"
    end
  end

  test "declaring the same capability twice is idempotent" do
    [ct] = DuplicateRequires.containers()
    assert ct.requires == [:"journal.local"]
    assert length(ct.socket_mounts) == 1
  end

  # ============================================================
  # DSL: env coexists with explicit env block
  # ============================================================

  defmodule RequiresWithEnv do
    use Erlkoenig.Container

    container :web do
      binary "/opt/bin/web"
      env %{"PORT" => "80", "MODE" => "prod"}
      requires :"journal.local"
    end
  end

  test "explicit env keys coexist with capability-injected env" do
    [ct] = RequiresWithEnv.containers()
    assert ct.env["PORT"] == "80"
    assert ct.env["MODE"] == "prod"
    assert ct.env["JOURNAL_LOCAL_SOCK"] == "/run/journal.sock"
  end

  # ============================================================
  # DSL: containers without requires stay clean
  # ============================================================

  defmodule NoRequires do
    use Erlkoenig.Container

    container :worker do
      binary "/opt/bin/worker"
    end
  end

  test "containers without requires omit the field from spawn opts" do
    [ct] = NoRequires.containers()
    refute Map.has_key?(ct, :requires)
    refute Map.has_key?(ct, :socket_mounts)
  end

  # ============================================================
  # DSL: unknown capability fails at compile time
  # ============================================================

  test "unknown capability raises a compile-time error" do
    assert_raise ArgumentError, ~r/unknown capability/, fn ->
      defmodule WillFail do
        use Erlkoenig.Container

        container :bad do
          binary "/opt/bin/bad"
          requires :"nonsense.local"
        end
      end
    end
  end
end
