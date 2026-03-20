#
# Unix socket client for erlkoenig control commands.
#
# Connects to /run/erlkoenig/ctl.sock and speaks the binary protocol.
#

defmodule Erlkoenig.Ctl do
  @default_sock "/run/erlkoenig/ctl.sock"

  @cmd_spawn           0x01
  @cmd_stop            0x02
  @cmd_ps              0x03
  @cmd_inspect         0x04
  @cmd_audit           0x06
  @cmd_status          0x07
  @cmd_push            0x10
  @cmd_artifacts       0x11
  @cmd_artifact_info   0x12
  @cmd_artifact_tag    0x13
  @cmd_artifact_delete 0x14

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

  # --- Ingestion commands (ETF payloads) ---

  @doc "Push a binary artifact to the daemon."
  def push(binary_path, opts \\ []) do
    binary_data = File.read!(binary_path)

    name =
      Keyword.get(opts, :name) ||
        Path.basename(binary_path, Path.extname(binary_path))

    tags = List.wrap(Keyword.get(opts, :tag, []))

    # Optional signing
    signature =
      if opts[:sign] do
        key = opts[:key] || raise "push --sign requires --key"
        cert = opts[:cert] || raise "push --sign requires --cert"

        case Erlkoenig.Sig.sign(binary_path, cert, key) do
          {:ok, sig_data} -> sig_data
          {:error, reason} -> raise "Signing failed: #{inspect(reason)}"
        end
      else
        nil
      end

    # Read extra files from directory
    files =
      if dir = opts[:files] do
        read_files_recursive(dir)
      else
        []
      end

    push_info = %{
      name: name,
      binary: binary_data,
      signature: signature,
      files: files,
      tags: tags
    }

    payload = :erlang.term_to_binary(push_info)
    call(:push, payload)
  end

  @doc "Decode a push response (ETF-encoded map)."
  def decode_push_response(payload) do
    :erlang.binary_to_term(payload)
  end

  @doc "List artifacts. Options: tag (binary) to filter."
  def artifacts(opts \\ []) do
    filter = %{}
    filter = if opts[:tag], do: Map.put(filter, :tag, opts[:tag]), else: filter

    payload =
      if map_size(filter) == 0, do: <<>>, else: :erlang.term_to_binary(filter)

    call(:artifacts, payload)
  end

  @doc "Decode an artifacts list response."
  def decode_artifacts_response(payload) do
    :erlang.binary_to_term(payload)
  end

  @doc "Get info about a single artifact."
  def artifact_info(name) do
    call(:artifact_info, :erlang.term_to_binary(name))
  end

  @doc "Decode an artifact info response."
  def decode_artifact_info_response(payload) do
    :erlang.binary_to_term(payload)
  end

  @doc "Tag an artifact."
  def tag_artifact(name, tag) do
    call(:artifact_tag, :erlang.term_to_binary({name, tag}))
  end

  @doc "Delete an artifact."
  def delete_artifact(name) do
    call(:artifact_delete, :erlang.term_to_binary(name))
  end

  @doc "Read all files in a directory recursively, returning [{relative_path, binary_data}]."
  def read_files_recursive(dir) do
    dir = Path.expand(dir)

    dir
    |> Path.join("**")
    |> Path.wildcard()
    |> Enum.filter(&File.regular?/1)
    |> Enum.map(fn path ->
      rel = Path.relative_to(path, dir)
      data = File.read!(path)
      {rel, data}
    end)
  end

  # --- Helpers ---

  defp cmd_byte(:spawn),           do: @cmd_spawn
  defp cmd_byte(:stop),            do: @cmd_stop
  defp cmd_byte(:ps),              do: @cmd_ps
  defp cmd_byte(:inspect),         do: @cmd_inspect
  defp cmd_byte(:audit),           do: @cmd_audit
  defp cmd_byte(:status),          do: @cmd_status
  defp cmd_byte(:push),            do: @cmd_push
  defp cmd_byte(:artifacts),       do: @cmd_artifacts
  defp cmd_byte(:artifact_info),   do: @cmd_artifact_info
  defp cmd_byte(:artifact_tag),    do: @cmd_artifact_tag
  defp cmd_byte(:artifact_delete), do: @cmd_artifact_delete

  defp encode_str(s) when is_binary(s) do
    <<byte_size(s)::big-16, s::binary>>
  end
  defp encode_str(s) when is_list(s), do: encode_str(:erlang.list_to_binary(s))
end
