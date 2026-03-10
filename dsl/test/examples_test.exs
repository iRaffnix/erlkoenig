defmodule Erlkoenig.ExamplesTest do
  use ExUnit.Case, async: false

  for path <- Path.wildcard("#{Path.expand("../examples", __DIR__)}/*.exs") do
    name = Path.basename(path, ".exs")

    describe "examples/#{name}.exs" do
      test "compiles to valid Erlang term" do
        path = unquote(path)
        output = Path.join(System.tmp_dir!(), "erlkoenig_ex_test_#{unquote(name)}.term")

        try do
          Erlkoenig.CLI.ExamplesTestHelper.compile(path, output)

          assert File.exists?(output), "output file not created"

          {:ok, [term]} = :file.consult(String.to_charlist(output))
          assert is_map(term), "compiled term is not a map"

          if Map.has_key?(term, :containers) do
            assert is_list(term.containers), "containers is not a list"
            assert length(term.containers) > 0, "no containers defined"
          end

          if Map.has_key?(term, :chains) do
            assert is_list(term.chains), "chains is not a list"
          end
        after
          File.rm(output)
        end
      end

      test "passes validation" do
        path = unquote(path)
        [{module, _} | _] = Code.compile_file(path)

        if function_exported?(module, :containers, 0) do
          containers = module.containers()
          assert is_list(containers)

          # no duplicate IPs
          ips = for %{ip: ip} <- containers, ip != nil, do: ip
          assert ips == Enum.uniq(ips), "duplicate IPs found"

          # no duplicate host ports
          ports = for %{} = ct <- containers, {hp, _} <- Map.get(ct, :ports, []), do: hp
          assert ports == Enum.uniq(ports), "duplicate host ports found"

          # all containers have binary and ip
          for ct <- containers do
            assert ct[:binary] != nil, "#{ct.name}: missing binary"
            assert ct[:ip] != nil, "#{ct.name}: missing IP"
          end
        end
      end
    end
  end
end

defmodule Erlkoenig.CLI.ExamplesTestHelper do
  @doc "Compile without System.halt — for test use."
  def compile(input, output) do
    modules = Code.compile_file(input)

    {mod, _} =
      case modules do
        [{mod, _}] -> {mod, nil}
        list ->
          Enum.find(list, fn {mod, _} ->
            function_exported?(mod, :containers, 0) or
              function_exported?(mod, :config, 0)
          end)
      end

    term =
      cond do
        function_exported?(mod, :containers, 0) ->
          config = %{containers: mod.containers()}
          config = if function_exported?(mod, :watches, 0),
            do: Map.put(config, :watches, mod.watches()), else: config
          config = if function_exported?(mod, :guard_config, 0) and mod.guard_config() != nil,
            do: Map.put(config, :guard, mod.guard_config()), else: config
          config

        function_exported?(mod, :config, 0) ->
          mod.config()
      end

    formatted = :io_lib.format(~c"~tp.~n", [term])
    File.write!(output, formatted)
  end
end
