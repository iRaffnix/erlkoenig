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

defmodule Erlkoenig.CLI do
  @moduledoc """
  Escript entry point for erlkoenig-dsl.

  Usage:
      erlkoenig-dsl compile config.exs [-o output.term]
      erlkoenig-dsl validate config.exs
  """

  @bash_completion ~S"""
  _erlkoenig_dsl() {
      local cur prev commands
      COMPREPLY=()
      cur="${COMP_WORDS[COMP_CWORD]}"
      prev="${COMP_WORDS[COMP_CWORD-1]}"
      commands="compile validate"

      case "$COMP_CWORD" in
          1)
              COMPREPLY=($(compgen -W "$commands --help" -- "$cur"))
              ;;
          *)
              case "$prev" in
                  compile|validate)
                      COMPREPLY=($(compgen -f -X '!*.exs' -- "$cur"))
                      ;;
                  -o)
                      COMPREPLY=($(compgen -f -X '!*.term' -- "$cur"))
                      ;;
                  *)
                      case "${COMP_WORDS[1]}" in
                          compile)
                              COMPREPLY=($(compgen -W "-o" -- "$cur"))
                              ;;
                      esac
                      ;;
              esac
              ;;
      esac
  }
  complete -o default -F _erlkoenig_dsl erlkoenig-dsl
  """

  @zsh_completion ~S"""
  #compdef erlkoenig-dsl

  _erlkoenig_dsl() {
      local -a commands
      commands=(
          'compile:Compile a DSL .exs file to an Erlang .term file'
          'validate:Check a DSL .exs file for errors'
      )

      _arguments -C \
          '1:command:->command' \
          '*::arg:->args'

      case "$state" in
          command)
              _describe 'command' commands
              ;;
          args)
              case "${words[1]}" in
                  compile)
                      _arguments \
                          '1:input file:_files -g "*.exs"' \
                          '-o[output file]:output file:_files -g "*.term"'
                      ;;
                  validate)
                      _arguments '1:input file:_files -g "*.exs"'
                      ;;
              esac
              ;;
      esac
  }

  _erlkoenig_dsl "$@"
  """

  def main(args) do
    case args do
      ["compile" | rest] -> compile(rest)
      ["validate" | rest] -> validate(rest)
      ["--completions", shell] -> completions(shell)
      [flag] when flag in ["--help", "-h"] -> usage()
      _ -> usage()
    end
  end

  defp compile(args) do
    {opts, files, _} =
      OptionParser.parse(args, strict: [output: :string], aliases: [o: :output])

    case files do
      [input_file] -> do_compile(input_file, opts)
      _ -> error("Usage: erlkoenig-dsl compile <file.exs> [-o output.term]")
    end
  end

  defp validate(args) do
    case args do
      [input_file] -> do_validate(input_file)
      _ -> error("Usage: erlkoenig-dsl validate <file.exs>")
    end
  end

  defp do_compile(input_file, opts) do
    check_file!(input_file)

    output_file =
      Keyword.get(opts, :output, Path.rootname(input_file) <> ".term")

    info("Compiling #{input_file} ...")

    mod = find_dsl_module(input_file)
    term = extract_term(mod)

    formatted = :io_lib.format(~c"~tp.~n", [term])
    File.write!(output_file, formatted)

    info("Written to #{output_file}")
  end

  defp do_validate(input_file) do
    check_file!(input_file)

    info("Validating #{input_file} ...")

    [{module, _}] = Code.compile_file(input_file)

    containers =
      if function_exported?(module, :containers, 0) do
        module.containers()
      else
        error("Module #{inspect(module)} has no containers/0 function")
      end

    errors = validate_containers(containers)

    case errors do
      [] ->
        info("OK - #{length(containers)} container(s), no errors")

      errs ->
        Enum.each(errs, fn e -> error_msg("  ERROR: #{e}") end)
        error("#{length(errs)} error(s) found")
    end
  end

  defp find_dsl_module(input_file) do
    modules = Code.compile_file(input_file)

    case modules do
      [{mod, _}] ->
        mod

      list when is_list(list) ->
        Enum.find_value(list, fn {mod, _} ->
          if function_exported?(mod, :containers, 0), do: mod
        end) || error("No module with containers/0 found")
    end
  end

  defp extract_term(module) do
    cond do
      function_exported?(module, :containers, 0) ->
        %{containers: module.containers()}

      true ->
        error("Module #{inspect(module)} has no containers/0 function")
    end
  end

  defp validate_containers(containers) do
    ip_errors = check_duplicate_ips(containers)
    port_errors = check_duplicate_ports(containers)
    field_errors = Enum.flat_map(containers, &check_container_fields/1)
    ip_errors ++ port_errors ++ field_errors
  end

  defp check_container_fields(%{name: name} = ct) do
    errs = []
    errs = if ct[:binary] == nil, do: errs ++ ["#{name}: missing binary path"], else: errs
    errs = if ct[:ip] == nil, do: errs ++ ["#{name}: missing IP address"], else: errs
    errs
  end

  defp check_duplicate_ips(containers) do
    ips = for %{ip: ip, name: name} <- containers, ip != nil, do: {ip, name}

    ips
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.filter(fn {_ip, names} -> length(names) > 1 end)
    |> Enum.map(fn {ip, names} ->
      "duplicate IP #{inspect(ip)} in containers: #{Enum.join(names, ", ")}"
    end)
  end

  defp check_duplicate_ports(containers) do
    ports =
      for %{name: name} = ct <- containers,
          {host_port, _} <- Map.get(ct, :ports, []),
          do: {host_port, name}

    ports
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.filter(fn {_port, names} -> length(names) > 1 end)
    |> Enum.map(fn {port, names} ->
      "duplicate host port #{port} in containers: #{Enum.join(names, ", ")}"
    end)
  end

  defp check_file!(path) do
    unless File.exists?(path) do
      error("File not found: #{path}")
    end
  end

  defp completions("bash") do
    IO.puts(@bash_completion)
  end

  defp completions("zsh") do
    IO.puts(@zsh_completion)
  end

  defp completions(other) do
    error("Unknown shell: #{other}. Supported: bash, zsh")
  end

  defp usage do
    IO.puts("""
    erlkoenig-dsl - Erlkoenig configuration compiler

    Usage:
        erlkoenig-dsl compile <file.exs> [-o output.term]
        erlkoenig-dsl validate <file.exs>
        erlkoenig-dsl --help

    Commands:
        compile     Compile a DSL .exs file to an Erlang .term file
        validate    Check a DSL .exs file for errors

    Shell completion:
        eval "$(erlkoenig-dsl --completions bash)"
        eval "$(erlkoenig-dsl --completions zsh)"
    """)

    System.halt(1)
  end

  defp info(msg), do: IO.puts(msg)
  defp error_msg(msg), do: IO.puts(:stderr, msg)

  defp error(msg) do
    IO.puts(:stderr, msg)
    System.halt(1)
  end
end
