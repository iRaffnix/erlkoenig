#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0
#

defmodule Erlkoenig.Capabilities do
  @moduledoc """
  Registry of node-local service capabilities a container can `requires`.

  Each entry describes the contract — host socket path, in-container
  socket path, env var to set — that the DSL injects when a container
  declares it. A walking-skeleton view of the broader capability
  framework outlined in the strategy memo
  `2026-04-19-node-sovereign-architecture` (currently one entry,
  `:journal.local`, with more landing as the catalog ships).

  Adding a capability is a one-tuple change here plus a runtime
  service that binds the named socket. The DSL needs no changes.
  """

  @type spec :: %{
          host_socket: String.t(),
          container_socket: String.t(),
          env_var: String.t()
        }

  @doc """
  Directory the capability sockets live in (host AND container side).

  All capabilities share `/run/erlkoenig/` by convention: one
  directory bind-mount in the container and every socket appears at
  the same absolute path in both namespaces. The C runtime can only
  bind directories today, so binding the parent dir lets us avoid
  per-file binds while keeping the socket paths predictable.
  """
  def socket_dir, do: "/run/erlkoenig/"

  @doc "Map of all known capabilities to their injection spec."
  @spec all() :: %{atom() => spec()}
  def all do
    %{
      :"journal.local" => %{
        host_socket: "/run/erlkoenig/journal.sock",
        container_socket: "/run/erlkoenig/journal.sock",
        env_var: "JOURNAL_LOCAL_SOCK"
      }
    }
  end

  @doc """
  Look up a capability's injection spec.

  Returns `{:ok, spec}` for a known capability, `{:error,
  {:unknown_capability, name, known}}` otherwise — `known` is the
  sorted list of valid names so the error message tells you what
  you might have meant.
  """
  @spec fetch(atom()) :: {:ok, spec()} | {:error, {:unknown_capability, atom(), [atom()]}}
  def fetch(name) when is_atom(name) do
    case Map.fetch(all(), name) do
      {:ok, spec} -> {:ok, spec}
      :error      -> {:error, {:unknown_capability, name,
                                 all() |> Map.keys() |> Enum.sort()}}
    end
  end

  @doc """
  Like `fetch/1` but raises with a helpful message for unknown capabilities.
  """
  @spec fetch!(atom()) :: spec()
  def fetch!(name) do
    case fetch(name) do
      {:ok, spec} -> spec
      {:error, {:unknown_capability, n, known}} ->
        raise ArgumentError,
          "unknown capability #{inspect(n)}; known: #{inspect(known)}"
    end
  end
end
