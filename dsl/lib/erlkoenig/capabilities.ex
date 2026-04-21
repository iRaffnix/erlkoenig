#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0
#

defmodule Erlkoenig.Capabilities do
  @moduledoc """
  Registry of node-local service capabilities a container can `requires`.

  Each entry has a **kind** that determines what the DSL injects:

    * `:socket` — Unix-domain socket service. The DSL bind-mounts the
      shared socket directory into the container and sets an env var
      pointing at the socket path. Example: `:"journal.local"`.

    * `:network` — Network-resident service the container reaches via
      its existing IP routing (e.g. zone gateway). The DSL records the
      dependency in `:requires` but injects no mount or env — the
      runtime already configures the network path (e.g. `/etc/resolv.conf`
      via the C runtime's `EK_ATTR_DNS_IP`). The declaration matters
      because it surfaces the dependency in the container term so
      operators can see what each container relies on, and is the
      future hook for opt-out enforcement.

  Adding a capability is a one-tuple change here. The DSL needs no
  changes per capability; the kind dispatches the right injection.
  """

  @type kind :: :socket | :network | :dns_allowlist

  @type socket_spec :: %{
          required(:kind) => :socket,
          required(:host_socket) => String.t(),
          required(:container_socket) => String.t(),
          required(:env_var) => String.t(),
          optional(:env_value) => String.t()
        }

  @type network_spec :: %{
          kind: :network,
          description: String.t()
        }

  @type dns_allowlist_spec :: %{
          kind: :dns_allowlist,
          description: String.t()
        }

  @type spec :: socket_spec() | network_spec() | dns_allowlist_spec()

  @doc """
  Directory the socket-kind capability sockets live in
  (host AND container side).

  All `:socket`-kind capabilities share `/run/erlkoenig/` by
  convention: one directory bind-mount in the container and every
  socket appears at the same absolute path in both namespaces.
  """
  def socket_dir, do: "/run/erlkoenig/"

  @doc "Map of all known capabilities to their injection spec."
  @spec all() :: %{atom() => spec()}
  def all do
    %{
      :"journal.local" => %{
        kind: :socket,
        host_socket: "/run/erlkoenig/journal.sock",
        container_socket: "/run/erlkoenig/journal.sock",
        env_var: "JOURNAL_LOCAL_SOCK"
      },
      :"dns.local" => %{
        kind: :network,
        description:
          "Per-zone DNS resolver (UDP/53 on the zone gateway IP). " <>
            "The container's /etc/resolv.conf is configured by the C " <>
            "runtime via the EK_ATTR_DNS_IP TLV; declaring this capability " <>
            "surfaces the dependency in the container term."
      },
      :"dns.allowlist" => %{
        kind: :dns_allowlist,
        description:
          "L7 egress allow-list for the per-zone DNS resolver " <>
            "(SPEC-AS-009). Takes a `:hosts` opt — a list of hostname " <>
            "patterns. The container's source IP is registered against " <>
            "this list at spawn time; lookups for non-matching names " <>
            "are answered with authoritative NXDOMAIN and audit-logged. " <>
            "Operator still owns the L4 nft policy that lets the " <>
            "container reach the resolver in the first place — " <>
            "Glasbox-Prinzip."
      },
      :"postgres.local" => %{
        kind: :socket,
        # Postgres always names its socket file `.s.PGSQL.<port>`
        # inside its `unix_socket_directories`; the dir-bind we
        # already do for socket-kind capabilities makes the file
        # appear at the same absolute path on both sides.
        host_socket: "/run/erlkoenig/.s.PGSQL.5432",
        container_socket: "/run/erlkoenig/.s.PGSQL.5432",
        # libpq reads PGHOST as a DIRECTORY when the value starts
        # with `/` and looks for `.s.PGSQL.<PGPORT>` inside.
        # Override the env_value so we expose the directory, not
        # the socket file.
        env_var: "PGHOST",
        env_value: "/run/erlkoenig"
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
      {:ok, spec} ->
        {:ok, spec}

      :error ->
        {:error, {:unknown_capability, name, all() |> Map.keys() |> Enum.sort()}}
    end
  end

  @doc """
  Like `fetch/1` but raises with a helpful message for unknown capabilities.
  """
  @spec fetch!(atom()) :: spec()
  def fetch!(name) do
    case fetch(name) do
      {:ok, spec} ->
        spec

      {:error, {:unknown_capability, n, known}} ->
        raise ArgumentError,
              "unknown capability #{inspect(n)}; known: #{inspect(known)}"
    end
  end
end
