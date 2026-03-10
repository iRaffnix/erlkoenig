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

defmodule Mix.Tasks.Erlkoenig.Validate do
  @moduledoc """
  Validate a Erlkoenig DSL .ek file without applying it.

  Compiles the file, extracts the config, and checks for common
  errors (missing binaries, invalid IPs, port conflicts, etc.).

  ## Usage

      mix erlkoenig.validate config.ek
  """

  use Mix.Task

  @shortdoc "Validate a Erlkoenig DSL config file"

  @impl Mix.Task
  def run(args) do
    case args do
      [input_file] ->
        validate_file(input_file)

      _ ->
        Mix.shell().error("Usage: mix erlkoenig.validate <file.ek>")
        System.halt(1)
    end
  end

  defp validate_file(input_file) do
    unless File.exists?(input_file) do
      Mix.shell().error("File not found: #{input_file}")
      System.halt(1)
    end

    Mix.shell().info("Validating #{input_file} ...")

    [{module, _}] = Code.compile_file(input_file)

    errors = []

    {containers, errors} =
      if function_exported?(module, :containers, 0) do
        cts = module.containers()
        errs = validate_containers(cts)
        {cts, errors ++ errs}
      else
        {[], errors}
      end

    errors =
      if function_exported?(module, :config, 0) do
        config = module.config()
        errors ++ validate_firewall(config)
      else
        errors
      end

    case errors do
      [] ->
        Mix.shell().info("OK - #{length(containers)} container(s), no errors")

      errs ->
        Enum.each(errs, fn e ->
          Mix.shell().error("  ERROR: #{e}")
        end)

        Mix.shell().error("#{length(errs)} error(s) found")
        System.halt(1)
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

    errs =
      if ct[:binary] == nil,
        do: errs ++ ["#{name}: missing binary path"],
        else: errs

    errs =
      if ct[:ip] == nil,
        do: errs ++ ["#{name}: missing IP address"],
        else: errs

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

  defp validate_firewall(%{chains: chains}) when is_list(chains) do
    Enum.flat_map(chains, fn
      %{rules: []} -> ["empty chain (no rules)"]
      _ -> []
    end)
  end

  defp validate_firewall(_), do: []
end
