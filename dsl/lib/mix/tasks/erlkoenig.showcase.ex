#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#

defmodule Mix.Tasks.Erlkoenig.Showcase do
  @moduledoc """
  Render an Erlkoenig DSL showcase as an ontology diagram.

  ## Known showcases

      mix erlkoenig.showcase resource_admission
        Renders examples/showcase/resource_admission_lab.exs as a
        Mermaid graph: stack → host (zones, nft) → pods → containers
        with their kill-factors, publish channels and per-container
        firewall.

  ## Custom files

      mix erlkoenig.showcase --file path/to/stack.exs

  ## Options

      --format mermaid  default; paste into a ```mermaid``` fence or
                        https://mermaid.live
      --format json     machine-readable fact list
      --format text     fact list grouped by type
      --file <path>     load an arbitrary stack `.exs` instead of a
                        known showcase
      --debug           render a container ownership/debug report
      --explain         instead of rendering the declared topology,
                        synthesise an `EK_CT_RESOURCE_ADMISSION_DENIED`
                        event from the showcase's container limits
                        and render the resulting causal world (same
                        shape the runtime would emit live). Useful
                        for showcases like `resource_admission_denial`
                        whose runtime denial is shadowed by the
                        config-load cross-validation.

  Unknown formats are rejected with exit code 2.

  ## Workstation-source tool

  This task resolves known showcases relative to the source tree
  (`__DIR__`-derived). It is not packaged into the OTP release —
  the dsl/ project is a build-time and operator-workstation
  artifact, not a runtime artifact. Run it from a checkout of the
  erlkoenig repo. To target a stack file from elsewhere on disk,
  use `--file <path>`.
  """

  @valid_formats ~w(text json mermaid)

  use Mix.Task

  alias Erlkoenig.Ontology.{Compiler, Debug, Fact, JsonRenderer, Mermaid, World}

  @shortdoc "Render an Erlkoenig DSL showcase as Mermaid (or text/JSON)"

  # Resolved at compile time so the task works regardless of which
  # directory the operator runs `mix` from. `__DIR__` is the source
  # location of this file (`dsl/lib/mix/tasks/`); going up four
  # levels lands at the repo root, where `examples/` lives.
  @project_root Path.expand("../../../..", __DIR__)

  @known_showcases %{
    "resource_admission" =>
      Path.join(@project_root, "examples/showcase/resource_admission_lab.exs"),
    "resource_admission_denial" =>
      Path.join(
        @project_root,
        "examples/showcase/resource_admission_denial_lab.exs"
      )
  }

  @impl Mix.Task
  def run(args) do
    case dispatch(args, &print/1) do
      :ok ->
        :ok

      {:error, exit_code, msg} ->
        Mix.shell().error(msg)
        System.halt(exit_code)
    end
  end

  # ------------------------------------------------------------------
  # Dispatch (testable: writer is injected; compile uses real disk)
  # ------------------------------------------------------------------

  @doc false
  def dispatch(args, write_output) do
    # Capture the third return — `invalid` carries unknown / mistyped
    # flags. OptionParser silently drops them; for an operator CLI a
    # `--formt mermaid` (typo) silently using the default format is
    # exactly the kind of glasbox failure we want to surface.
    {opts, positional, invalid} =
      OptionParser.parse(args,
        strict: [format: :string, file: :string, debug: :boolean, explain: :boolean],
        aliases: [f: :format]
      )

    format = Keyword.get(opts, :format, "mermaid")
    debug = Keyword.get(opts, :debug, false)
    explain = Keyword.get(opts, :explain, false)

    cond do
      invalid != [] ->
        {:error, 2, "unknown option(s): " <> format_invalid(invalid)}

      format not in @valid_formats ->
        {:error, 2,
         "unknown --format: #{inspect(format)}; " <>
           "must be one of: #{Enum.join(@valid_formats, " | ")}"}

      debug and explain ->
        {:error, 2, "--debug renders declared topology; combine neither with --explain"}

      debug and format != "text" ->
        {:error, 2, "--debug only supports --format text"}

      true ->
        with {:ok, path} <- resolve_path(positional, opts),
             {:ok, module} <- compile_and_get_module(path),
             %World{} = world <- safe_ontology(module),
             {:ok, render_world} <- maybe_synthesize_denial(world, explain) do
          write_output.(render(render_world, format, debug))
          :ok
        else
          {:error, _, _} = err -> err
          {:error, msg} -> {:error, 2, msg}
        end
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

  # ------------------------------------------------------------------
  # --explain — synthesise a runtime denial from declared limits
  # ------------------------------------------------------------------

  defp maybe_synthesize_denial(world, false), do: {:ok, world}

  defp maybe_synthesize_denial(world, true) do
    case synthesize_denial(world) do
      {:ok, denial} -> {:ok, Compiler.from_admission_denial(denial)}
      {:error, msg} -> {:error, 2, msg}
    end
  end

  @doc false
  @spec synthesize_denial(World.t()) :: {:ok, map()} | {:error, String.t()}
  def synthesize_denial(%World{facts: facts}) do
    # Walk containers in *declaration order* — `Compiler.from_stack`
    # already reverses the accumulator so `world.facts` reflects the
    # order operators see in their DSL. The last container with a
    # declared memory limit is the one a sequential spawn would
    # have tried last and therefore the one the gate would have
    # rejected; everything before it is treated as already-allocated
    # holders. This matches the operator-natural narrative
    # "worker-0 grabbed the budget, worker-1 was rejected".
    containers = Enum.filter(facts, &container_with_memory?/1)

    case Enum.reverse(containers) do
      [] ->
        {:error,
         "--explain: showcase has no containers with declared " <>
           "memory limits — nothing to synthesize a denial from"}

      [rejected | reversed_holders] ->
        holders = Enum.reverse(reversed_holders)
        {:ok, build_denial(rejected, holders)}
    end
  end

  defp container_with_memory?(%Fact{type: :container, properties: p}) do
    case Map.get(p, :limits) do
      %{} = limits ->
        m = Map.get(limits, :memory) || Map.get(limits, "memory")
        is_integer(m) and m > 0

      _ ->
        false
    end
  end

  defp container_with_memory?(_), do: false

  defp memory_of(%Fact{properties: p}) do
    p |> Map.get(:limits, %{}) |> Map.get(:memory, 0)
  end

  defp build_denial(rejected, holders) do
    required = memory_of(rejected)

    allocated_sources =
      Enum.map(holders, fn h ->
        %{
          id: container_label(h),
          name: Map.get(h.properties, :name),
          kind: :memory,
          value: memory_of(h)
        }
      end)

    allocated = Enum.reduce(allocated_sources, 0, &(&1.value + &2))

    # Make `available` strictly less than `required` so the
    # diagram shows a clean "insufficient" story. Pick a small
    # but visible slack so the snapshot label is not just zero.
    available = max(div(required, 8), 1)
    ceiling = allocated + available

    pids = rejected.properties |> Map.get(:limits, %{}) |> Map.get(:pids, 0)

    %{
      container_id: container_label(rejected),
      limits: %{memory: required, pids: pids},
      reason: %{
        reason: :insufficient_memory,
        required: required,
        available: available,
        evidence: %{
          kind: :memory,
          ceiling: ceiling,
          allocated: allocated,
          committed: 0,
          last_updated: System.system_time(:millisecond),
          allocated_sources: allocated_sources,
          committed_sources: []
        }
      }
    }
  end

  defp container_label(%Fact{ref: {_t, id}, properties: p}) do
    Map.get(p, :name) || to_string(id)
  end

  # ------------------------------------------------------------------
  # Path resolution
  # ------------------------------------------------------------------

  defp resolve_path([name], _opts) when is_map_key(@known_showcases, name) do
    {:ok, @known_showcases[name]}
  end

  defp resolve_path([], opts) do
    case Keyword.get(opts, :file) do
      nil -> {:error, 2, usage()}
      file -> {:ok, Path.expand(file)}
    end
  end

  defp resolve_path([unknown], _opts) do
    {:error, 2, "unknown showcase: #{unknown}. Known: #{known_names()}.\n" <> usage()}
  end

  defp resolve_path(_, _), do: {:error, 2, usage()}

  defp known_names, do: @known_showcases |> Map.keys() |> Enum.join(" | ")

  defp usage do
    "Usage:\n" <>
      "  mix erlkoenig.showcase <#{known_names()}> [--format mermaid|json|text]\n" <>
      "  mix erlkoenig.showcase <#{known_names()}> --debug --format text\n" <>
      "  mix erlkoenig.showcase --file <stack.exs> [--format mermaid|json|text]"
  end

  # ------------------------------------------------------------------
  # Compile + ontology extraction
  # ------------------------------------------------------------------

  defp compile_and_get_module(path) do
    case File.exists?(path) do
      false ->
        {:error, 2, "file not found: #{path}"}

      true ->
        try do
          # Best-effort purge of any previously loaded version so a
          # second invocation in the same VM (tests, mix shell) gets
          # the on-disk source, not a stale beam.
          maybe_purge_module_for(path)
          [{module, _bin}] = Code.compile_file(path)
          {:ok, module}
        rescue
          e ->
            {:error, 2, "compile failed: #{Exception.message(e)}"}
        end
    end
  end

  defp maybe_purge_module_for(_path) do
    # We don't know the module name until compile_file runs. The
    # purge happens on the next invocation if the previous compile
    # registered a module — we can't predict which one ahead of time
    # without reading the file. Code.compile_file/1 transparently
    # replaces any existing module of the same name, so this hook is
    # mostly for explicit lifecycle if a future operator wants it.
    :ok
  end

  defp safe_ontology(module) do
    if function_exported?(module, :ontology, 0) do
      module.ontology()
    else
      {:error, 2,
       "module #{inspect(module)} does not export ontology/0 — " <>
         "is it a `use Erlkoenig.Stack` module?"}
    end
  end

  # ------------------------------------------------------------------
  # Rendering (pure, mirrors explain task)
  # ------------------------------------------------------------------

  @doc false
  @spec render(World.t(), String.t()) :: iodata()
  def render(world, format), do: render(world, format, false)

  @doc false
  @spec render(World.t(), String.t(), boolean()) :: iodata()
  def render(%World{} = world, "text", true), do: [Debug.render(world), ?\n]

  def render(%World{} = world, "mermaid", false), do: [Mermaid.render(world), ?\n]

  def render(%World{} = world, "json", false) do
    [:json.encode(JsonRenderer.world_to_jsonable(world)), ?\n]
  end

  def render(%World{facts: facts}, "text", false) do
    grouped =
      facts
      |> Enum.group_by(& &1.type)
      |> Enum.sort_by(fn {type, _} -> Atom.to_string(type) end)

    header = "\n  Showcase ontology — #{length(facts)} facts\n\n"

    body =
      Enum.map(grouped, fn {type, group} ->
        [
          "  ",
          Atom.to_string(type),
          " (",
          Integer.to_string(length(group)),
          ")\n",
          Enum.map(group, &fact_text/1),
          "\n"
        ]
      end)

    [header, body]
  end

  defp fact_text(%{ref: {_type, id}}), do: ["    ", to_string(id), ?\n]

  defp print(iodata), do: IO.write(iodata)
end
