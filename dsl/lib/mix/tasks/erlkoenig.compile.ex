#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule Mix.Tasks.Erlkoenig.Compile do
  @moduledoc """
  Compile a Erlkoenig DSL .exs file to an Erlang .term file.

  ## Usage

      mix erlkoenig.compile config.exs
      mix erlkoenig.compile config.exs -o /etc/erlkoenig/cluster.term

  The .exs file must define a module that uses `Erlkoenig.DSL` (or
  `Erlkoenig.Container` directly) and implements a `containers/0` function.
  """

  use Mix.Task

  @shortdoc "Compile a Erlkoenig DSL file to an Erlang term"

  @impl Mix.Task
  def run(args) do
    {opts, files, _} =
      OptionParser.parse(args, strict: [output: :string], aliases: [o: :output])

    case files do
      [input_file] ->
        compile_file(input_file, opts)

      [] ->
        Mix.shell().error("Usage: mix erlkoenig.compile <file.exs> [-o output.term]")
        System.halt(1)

      _ ->
        Mix.shell().error("Expected exactly one input file")
        System.halt(1)
    end
  end

  defp compile_file(input_file, opts) do
    unless File.exists?(input_file) do
      Mix.shell().error("File not found: #{input_file}")
      System.halt(1)
    end

    output_file =
      Keyword.get(opts, :output, Path.rootname(input_file) <> ".term")

    Mix.shell().info("Compiling #{input_file} ...")

    mod = find_dsl_module(input_file)
    term = extract_term(mod)

    formatted = :io_lib.format(~c"~tp.~n", [term])
    File.write!(output_file, formatted)

    Mix.shell().info("Written to #{output_file}")
  end

  defp find_dsl_module(input_file) do
    modules = Code.compile_file(input_file)

    case modules do
      [{mod, _}] ->
        mod

      list when is_list(list) ->
        Enum.find_value(list, fn {mod, _} ->
          if function_exported?(mod, :config, 0) or function_exported?(mod, :containers, 0), do: mod
        end) ||
          (Mix.shell().error("No module with config/0 or containers/0 found")
           System.halt(1))
    end
  end

  defp extract_term(module) do
    cond do
      function_exported?(module, :config, 0) ->
        module.config()
      function_exported?(module, :containers, 0) ->
        %{containers: module.containers()}
      true ->
        Mix.shell().error("Module #{inspect(module)} has no config/0 or containers/0 function")
        System.halt(1)
    end
  end
end
