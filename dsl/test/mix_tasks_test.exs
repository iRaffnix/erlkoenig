defmodule Erlkoenig.MixTasksTest do
  use ExUnit.Case, async: true

  describe "mix erlkoenig.compile" do
    test "compiles example to term file" do
      input = Path.join([__DIR__, "..", "examples", "web_cluster.exs"]) |> Path.expand()
      output = Path.join(System.tmp_dir!(), "erlkoenig_compile_test_#{:rand.uniform(100000)}.term")

      Mix.Tasks.Erlkoenig.Compile.run([input, "-o", output])

      assert File.exists?(output)
      content = File.read!(output)

      # Verify it's a valid Erlang term
      assert content =~ "containers"
      assert content =~ "web_api"
      assert content =~ "worker"
      assert content =~ "redis"

      # Verify it can be parsed back
      {:ok, [term]} = :file.consult(String.to_charlist(output))
      assert is_map(term)
      assert length(term.containers) == 3

      File.rm!(output)
    end

    test "compiled term includes watches and guard" do
      input = Path.join([__DIR__, "..", "examples", "web_cluster.exs"]) |> Path.expand()
      output = Path.join(System.tmp_dir!(), "erlkoenig_compile_test2_#{:rand.uniform(100000)}.term")

      Mix.Tasks.Erlkoenig.Compile.run([input, "-o", output])

      {:ok, [term]} = :file.consult(String.to_charlist(output))
      assert Map.has_key?(term, :watches)
      assert Map.has_key?(term, :guard)
      assert length(term.watches) == 1
      assert term.guard.conn_flood == {100, 10}

      File.rm!(output)
    end
  end

  describe "mix erlkoenig.validate" do
    test "validates correct config" do
      input = Path.join([__DIR__, "..", "examples", "web_cluster.exs"]) |> Path.expand()
      # Should not raise or exit
      Mix.Tasks.Erlkoenig.Validate.run([input])
    end
  end
end
