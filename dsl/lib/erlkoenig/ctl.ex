#
# Unix socket client for erlkoenig control commands.
#
# Connects to /run/erlkoenig/ctl.sock and speaks the binary protocol.
#

defmodule Erlkoenig.Ctl do
  @default_sock "/run/erlkoenig/ctl.sock"

  @cmd_spawn   0x01
  @cmd_stop    0x02
  @cmd_ps      0x03
  @cmd_inspect 0x04
  @cmd_audit   0x06
  @cmd_status  0x07

  @doc "Connect, send request, receive response, close."
  def call(cmd, payload \\ <<>>, opts \\ []) do
    sock_path = Keyword.get(opts, :socket, @default_sock)
    req_id = :rand.uniform(0xFFFFFFFF)

    request = <<req_id::big-32, cmd_byte(cmd)::8, payload::binary>>

    case :gen_tcp.connect({:local, sock_path}, 0, [:binary, active: false, packet: 4], 5000) do
      {:ok, sock} ->
        :gen_tcp.send(sock, request)
        result = case :gen_tcp.recv(sock, 0, 10_000) do
          {:ok, <<^req_id::big-32, 0::8, resp_payload::binary>>} ->
            {:ok, resp_payload}
          {:ok, <<^req_id::big-32, 1::8, resp_payload::binary>>} ->
            {:error, resp_payload}
          {:ok, _other} ->
            {:error, "unexpected response"}
          {:error, reason} ->
            {:error, "recv failed: #{inspect(reason)}"}
        end
        :gen_tcp.close(sock)
        result

      {:error, :enoent} ->
        {:error, "erlkoenig is not running (socket not found: #{sock_path})"}

      {:error, :eacces} ->
        {:error, "permission denied (run as root or member of erlkoenig group)"}

      {:error, reason} ->
        {:error, "cannot connect: #{inspect(reason)}"}
    end
  end

  def spawn_container(binary_path, opts_json \\ "{}") do
    payload = encode_str(binary_path) <> encode_str(opts_json)
    call(:spawn, payload)
  end

  def stop_container(container_id) do
    call(:stop, encode_str(container_id))
  end

  def ps, do: call(:ps)

  def inspect_container(container_id) do
    call(:inspect, encode_str(container_id))
  end

  def audit(opts_json \\ "{}") do
    call(:audit, encode_str(opts_json))
  end

  def status, do: call(:status)

  # --- Helpers ---

  defp cmd_byte(:spawn),   do: @cmd_spawn
  defp cmd_byte(:stop),    do: @cmd_stop
  defp cmd_byte(:ps),      do: @cmd_ps
  defp cmd_byte(:inspect), do: @cmd_inspect
  defp cmd_byte(:audit),   do: @cmd_audit
  defp cmd_byte(:status),  do: @cmd_status

  defp encode_str(s) when is_binary(s) do
    <<byte_size(s)::big-16, s::binary>>
  end
  defp encode_str(s) when is_list(s), do: encode_str(:erlang.list_to_binary(s))
end
