defmodule Erlkoenig.ExamplesTest do
  use ExUnit.Case, async: false

  for path <- Path.wildcard("#{Path.expand("../examples", __DIR__)}/*.exs") do
    name = Path.basename(path, ".exs")

    test "examples/#{name}.exs compiles and validates" do
      path = unquote(path)
      output = Path.join(System.tmp_dir!(), "erlkoenig_ex_test_#{unquote(name)}.term")

      try do
        Mix.Tasks.Erlkoenig.Compile.run([path, "-o", output])

        assert File.exists?(output), "output file not created"

        {:ok, [term]} = :file.consult(String.to_charlist(output))
        assert is_map(term), "compiled term is not a map"

        if Map.has_key?(term, :containers) do
          containers = term.containers
          assert is_list(containers), "containers is not a list"
          assert length(containers) > 0, "no containers defined"

          # no duplicate IPs
          ips = for %{ip: ip} <- containers, ip != nil, do: ip
          assert ips == Enum.uniq(ips), "duplicate IPs found"

          # no duplicate host ports
          ports = for ct <- containers, {hp, _} <- Map.get(ct, :ports, []), do: hp
          assert ports == Enum.uniq(ports), "duplicate host ports found"

          # all containers have binary and ip
          for ct <- containers do
            assert ct[:binary] != nil, "#{ct.name}: missing binary"
            assert ct[:ip] != nil, "#{ct.name}: missing IP"
          end
        end
      after
        File.rm(output)
      end
    end
  end
end
