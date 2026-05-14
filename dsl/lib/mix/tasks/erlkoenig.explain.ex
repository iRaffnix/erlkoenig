#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

defmodule Mix.Tasks.Erlkoenig.Explain do
  @moduledoc """
  Explain operational decisions made by the erlkoenig runtime.

  ## Subcommands

      mix erlkoenig.explain admission

  Reads a `EK_CT_RESOURCE_ADMISSION_DENIED` event from stdin — the JSON
  shape produced by `ek admission denial <id> --format json` on the
  host — and prints a structured trace.

  ## Usage

      ssh erlkoenig-2 'ek admission denial api --format json' \
        | mix erlkoenig.explain admission

      cat denial.json | mix erlkoenig.explain admission --format json

  ## Options

      --format text     default; human-readable trace
      --format json     machine-readable fact list (`type/id/properties/links`)
      --format mermaid  causal graph in Mermaid syntax — paste into a
                        ```mermaid``` fence or https://mermaid.live

  Unknown formats are rejected with exit code 2.
  """

  @valid_formats ~w(text json mermaid)

  use Mix.Task

  alias Erlkoenig.Ontology.{Compiler, JsonRenderer, Mermaid, World}

  @shortdoc "Explain runtime decisions (admission denials, ...)"

  @impl Mix.Task
  def run(args) do
    case dispatch(args, &read_stdin/0, &print/1) do
      :ok -> :ok
      {:error, exit_code, msg} ->
        Mix.shell().error(msg)
        System.halt(exit_code)
    end
  end

  # ------------------------------------------------------------------
  # Dispatch (testable: I/O is injected)
  # ------------------------------------------------------------------

  @doc false
  def dispatch(args, read_input, write_output) do
    # Capture the third return — `invalid` carries unknown / mistyped
    # flags. OptionParser silently drops them; for an operator CLI
    # `--formt json` (typo) silently using the default format is
    # exactly the kind of glasbox failure we want to surface.
    {opts, positional, invalid} =
      OptionParser.parse(args,
        strict: [format: :string],
        aliases: [f: :format]
      )

    cond do
      invalid != [] ->
        {:error, 2, "unknown option(s): " <> format_invalid(invalid)}

      true ->
        dispatch_admission(opts, positional, read_input, write_output)
    end
  end

  defp dispatch_admission(opts, positional, read_input, write_output) do
    case positional do
      ["admission"] ->
        format = Keyword.get(opts, :format, "text")

        if format in @valid_formats do
          explain_admission(read_input.(), format, write_output)
        else
          {:error, 2,
           "unknown --format: #{inspect(format)}; " <>
             "must be one of: #{Enum.join(@valid_formats, " | ")}"}
        end

      _ ->
        {:error, 2,
         "Usage: mix erlkoenig.explain admission " <>
           "[--format=text|json|mermaid]"}
    end
  end

  defp format_invalid(invalid) do
    invalid
    |> Enum.map(fn
      {flag, nil} -> flag
      {flag, value} -> "#{flag}=#{value}"
    end)
    |> Enum.join(", ")
  end

  defp explain_admission(:eof, _format, _write),
    do: {:error, 2, "erlkoenig.explain admission: empty stdin"}

  defp explain_admission("", _format, _write),
    do: {:error, 2, "erlkoenig.explain admission: empty stdin"}

  defp explain_admission(body, format, write) when is_binary(body) do
    with {:ok, event} <- decode_json(body),
         %World{} = world <- Compiler.from_emit_event(event) do
      write.(render(world, format))
      :ok
    else
      {:error, {:unknown_event_shape, _}} ->
        {:error, 2,
         "stdin is not a EK_CT_RESOURCE_ADMISSION_DENIED event " <>
           "(check the upstream emitted the right shape)"}

      {:error, reason} ->
        {:error, 2, "not valid JSON: #{inspect(reason)}"}
    end
  end

  # ------------------------------------------------------------------
  # Rendering (pure)
  # ------------------------------------------------------------------

  @doc false
  @spec render(World.t(), String.t()) :: iodata()
  def render(%World{} = world, "json") do
    [:json.encode(JsonRenderer.world_to_jsonable(world)), ?\n]
  end

  def render(%World{} = world, "mermaid") do
    [Mermaid.render(world), ?\n]
  end

  def render(%World{facts: facts}, "text") do
    grouped =
      facts
      |> Enum.group_by(& &1.type)
      |> Enum.sort_by(fn {type, _} -> type_order(type) end)

    header = "\n  Admission denial trace — #{length(facts)} facts\n\n"

    body =
      Enum.map(grouped, fn {type, group} ->
        [
          "  ", Atom.to_string(type), " (", Integer.to_string(length(group)), ")\n",
          Enum.map(group, &fact_text/1),
          "\n"
        ]
      end)

    [header, body]
  end

  # Stable display order: rejected request first, then what it asked for,
  # then the snapshot, then the holders that made room insufficient.
  defp type_order(:admission_denial), do: 0
  defp type_order(:resource_request), do: 1
  defp type_order(:capacity_snapshot), do: 2
  defp type_order(:resource_holder), do: 3
  defp type_order(_), do: 99

  defp fact_text(%{ref: {_type, id}, properties: props}) do
    rendered_props =
      props
      |> Enum.sort_by(fn {k, _} -> to_string(k) end)
      |> Enum.map(fn {k, v} -> ["      ", to_string(k), " = ", inspect(v), ?\n] end)

    ["    ", to_string(id), ?\n, rendered_props]
  end

  # ------------------------------------------------------------------
  # I/O helpers
  # ------------------------------------------------------------------

  defp read_stdin do
    case IO.read(:stdio, :eof) do
      :eof -> :eof
      {:error, _} = e -> e
      data when is_binary(data) -> data
    end
  end

  defp print(iodata) do
    IO.write(iodata)
  end

  defp decode_json(body) do
    try do
      {:ok, :json.decode(body)}
    rescue
      e -> {:error, e}
    catch
      _, e -> {:error, e}
    end
  end
end
