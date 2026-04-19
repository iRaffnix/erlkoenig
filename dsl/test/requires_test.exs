defmodule Erlkoenig.RequiresTest do
  use ExUnit.Case, async: true

  alias Erlkoenig.Capabilities

  # ============================================================
  # Capabilities registry
  # ============================================================

  describe "Capabilities registry" do
    test "knows :journal.local as :socket kind" do
      assert {:ok, spec} = Capabilities.fetch(:"journal.local")
      assert spec.kind == :socket
      assert spec.host_socket == "/run/erlkoenig/journal.sock"
      assert spec.container_socket == "/run/erlkoenig/journal.sock"
      assert spec.env_var == "JOURNAL_LOCAL_SOCK"
    end

    test "knows :dns.local as :network kind" do
      assert {:ok, spec} = Capabilities.fetch(:"dns.local")
      assert spec.kind == :network
      assert is_binary(spec.description)
      refute Map.has_key?(spec, :host_socket)
      refute Map.has_key?(spec, :env_var)
    end

    test "all :socket-kind sockets share socket_dir/0" do
      dir = Capabilities.socket_dir()

      Capabilities.all()
      |> Enum.filter(fn {_, s} -> s.kind == :socket end)
      |> Enum.each(fn {_name, spec} ->
        assert String.starts_with?(spec.host_socket, dir),
               "host_socket #{spec.host_socket} not under #{dir}"
        assert String.starts_with?(spec.container_socket, dir),
               "container_socket #{spec.container_socket} not under #{dir}"
      end)
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

    test "injects the env var pointing at the same-path socket", %{ct: ct} do
      assert ct.env["JOURNAL_LOCAL_SOCK"] == "/run/erlkoenig/journal.sock"
    end

    test "adds a directory bind-mount, not a file bind-mount", %{ct: ct} do
      assert ct.socket_mounts == [
               %{host: "/run/erlkoenig/",
                 container: "/run/erlkoenig/",
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
    assert ct.env["JOURNAL_LOCAL_SOCK"] == "/run/erlkoenig/journal.sock"
  end

  # ============================================================
  # DSL: multiple capabilities collapse to one dir-bind
  # ============================================================
  #
  # We can't add a second real capability to the registry just for
  # this test, so we exercise the dedup logic via two `requires`
  # of the same capability — `add_requires` is also where dedup of
  # the dir-bind happens.

  defmodule TwoRequiresCollapseDir do
    use Erlkoenig.Container

    container :app do
      binary "/opt/bin/app"
      requires :"journal.local"
      requires :"journal.local"
    end
  end

  test "duplicate requires collapse to one dir-bind" do
    [ct] = TwoRequiresCollapseDir.containers()
    assert length(ct.socket_mounts) == 1
    assert hd(ct.socket_mounts).host == "/run/erlkoenig/"
  end

  # ============================================================
  # DSL: :network-kind capability (dns.local) — declarative-only
  # ============================================================

  defmodule WithDns do
    use Erlkoenig.Container

    container :web do
      binary "/opt/bin/web"
      requires :"dns.local"
    end
  end

  describe "container with :network-kind requires" do
    setup do
      [ct] = WithDns.containers()
      {:ok, ct: ct}
    end

    test "records the capability in :requires", %{ct: ct} do
      assert ct.requires == [:"dns.local"]
    end

    test "does NOT add a socket mount", %{ct: ct} do
      # to_spawn_opts strips empty fields, so :socket_mounts may be absent.
      assert Map.get(ct, :socket_mounts, []) == []
    end

    test "does NOT inject any env var", %{ct: ct} do
      assert Map.get(ct, :env, %{}) == %{}
    end
  end

  # ============================================================
  # DSL: mixing kinds — both surface in :requires, only :socket
  #      affects mounts/env
  # ============================================================

  defmodule MixedKinds do
    use Erlkoenig.Container

    container :app do
      binary "/opt/bin/app"
      requires :"journal.local"
      requires :"dns.local"
    end
  end

  test "mixed-kind requires: socket cap injects, network cap declarative-only" do
    [ct] = MixedKinds.containers()
    assert ct.requires == [:"journal.local", :"dns.local"]
    # journal.local pulled in the dir-bind + env
    assert length(ct.socket_mounts) == 1
    assert hd(ct.socket_mounts).host == "/run/erlkoenig/"
    assert ct.env["JOURNAL_LOCAL_SOCK"] == "/run/erlkoenig/journal.sock"
    # dns.local added nothing beyond the :requires entry
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
