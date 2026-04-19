# examples/journal_demo.exs
#
# Runnable end-to-end demo for the `requires :"journal.local"`
# capability. Designed to be invoked from `dsl/` as:
#
#     cd dsl
#     mix run ../examples/journal_demo.exs
#
# What it does, in order:
#   1. Wires the Erlang BEAM ebin paths into the VM so we can talk
#      to `:erlkoenig_audit` and `:erlkoenig_journal_local` from
#      Elixir. (Mix doesn't know about the Erlang side.)
#   2. Defines a one-container DSL stack that `requires
#      :"journal.local"`. Prints the resulting term so you can see
#      the auto-injected env var, socket mount, and capability list.
#   3. Starts the audit + journal daemons on a /tmp sandbox path.
#      No root, no /run/erlkoenig, no production state touched.
#   4. Spawns a tiny "workload" process that connects to the
#      socket the DSL pointed at via env var, sends three JSON
#      log lines, then closes.
#   5. Verifies the resulting audit chain.
#
# Caveat: in production the runtime sets up the bind-mount the DSL
# describes (`socket_mounts`) so the container sees the socket at
# its in-namespace path. This demo runs without containers, so the
# workload uses the host path directly. The DSL term is the same
# either way — only the path resolution differs.

# --- 1. Code path: pull in the Erlang ebins ---

erlang_ebins =
  [Path.expand("../_build/default/lib/*/ebin", __DIR__)]
  |> Enum.flat_map(&Path.wildcard/1)
  |> Enum.map(&String.to_charlist/1)

case erlang_ebins do
  [] ->
    IO.puts(:stderr, """
    No Erlang BEAM files found under _build/default/lib/*/ebin.
    Run `make erl` from the project root first.
    """)
    System.halt(1)

  ebins ->
    Enum.each(ebins, &:code.add_pathz/1)
end

# --- 2. The DSL stack ---

defmodule JournalDemoStack do
  use Erlkoenig.Container

  container :web do
    binary "/opt/bin/web"   # placeholder; we don't actually spawn it
    ip {10, 0, 0, 10}
    requires :"journal.local"
  end
end

[ct] = JournalDemoStack.containers()

IO.puts("\n=== DSL output ===")
IO.puts("requires      : #{inspect(ct.requires)}")
IO.puts("env injected  : JOURNAL_LOCAL_SOCK = #{ct.env["JOURNAL_LOCAL_SOCK"]}")
IO.puts("socket_mount  : #{inspect(hd(ct.socket_mounts))}")

# --- 3. Sandbox + start daemons ---

sandbox =
  "/tmp/ek-journal-demo-#{System.system_time(:microsecond)}-#{System.unique_integer([:positive])}"

File.mkdir_p!(sandbox)
audit_path = Path.join(sandbox, "audit.jsonl")
sock_path  = Path.join(sandbox, "journal.sock")

:application.set_env(:erlkoenig, :audit_path, String.to_charlist(audit_path))
:application.set_env(:erlkoenig, :journal_local_path, String.to_charlist(sock_path))

# Tutorial-friendly: suppress the audit/journal :info startup lines
# so the demo's own headings stay legible.
:logger.set_primary_config(:level, :warning)

{:ok, audit_pid}    = :erlkoenig_audit.start_link()
{:ok, _journal_pid} = :erlkoenig_journal_local.start_link()

IO.puts("\n=== daemons up ===")
IO.puts("audit_path : #{audit_path}")
IO.puts("socket     : #{sock_path}")

# --- 4. Workload — uses the env var the DSL set ---
#
# In production the runtime would have bind-mounted the host socket
# to the in-container path stored in env. Here, no container = no
# namespace, so we override JOURNAL_LOCAL_SOCK with the host path
# for this single-process demo.
System.put_env("JOURNAL_LOCAL_SOCK", sock_path)

journal_sock = System.get_env("JOURNAL_LOCAL_SOCK")
{:ok, sock} =
  :gen_tcp.connect(
    {:local, String.to_charlist(journal_sock)},
    0,
    [:binary, packet: :line, active: false],
    2_000
  )

send_line = fn map ->
  encoded = :erlang.iolist_to_binary(:json.encode(map))
  :gen_tcp.send(sock, [encoded, ?\n])
end

send_line.(%{"subject" => "web", "level" => "info",
             "msg" => "starting", "fields" => %{"port" => 8080}})
send_line.(%{"subject" => "web", "level" => "info",
             "msg" => "ready"})
send_line.(%{"subject" => "web", "level" => "warn",
             "msg" => "slow request", "fields" => %{"ms" => 1234}})

:gen_tcp.close(sock)

# Give the daemon a moment to fan out into the audit cast.
Process.sleep(150)
:erlkoenig_audit.query(%{limit: 0})  # synchronous flush
Process.sleep(50)

# --- 5. Verify the chain ---

result = :erlkoenig_audit.verify_chain(String.to_charlist(audit_path))
IO.puts("\n=== verify_chain ===")
IO.puts(inspect(result))

# Show the journal-typed events that landed.
{:ok, raw} = File.read(audit_path)
events =
  raw
  |> String.split("\n", trim: true)
  |> Enum.map(&:json.decode/1)

IO.puts("\n=== chain content (#{length(events)} events) ===")
Enum.each(events, fn e ->
  IO.puts("seq=#{e["seq"]}  type=#{e["type"]}  subject=#{e["subject"]}  msg=#{e["msg"]}")
end)

# --- Cleanup ---

:erlkoenig_journal_local.stop()
GenServer.stop(audit_pid)
File.rm_rf!(sandbox)

case result do
  {:ok, _} ->
    IO.puts("\n=== demo passed ===")
    System.halt(0)

  _ ->
    IO.puts("\n=== demo FAILED ===")
    System.halt(1)
end
