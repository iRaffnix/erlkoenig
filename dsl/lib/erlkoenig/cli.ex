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
  Escript entry point for erlkoenig.

  Local commands (no daemon needed):
      erlkoenig compile stack.exs [-o output.term]
      erlkoenig validate stack.exs
      erlkoenig show stack.exs
      erlkoenig sign <binary> --cert <cert.pem> --key <key.pem>
      erlkoenig verify <binary> [--trust-root <ca.pem>]
      erlkoenig pki create-root-ca ...

  Runtime commands (via Erlang distribution):
      erlkoenig ps
      erlkoenig stop <id>
      erlkoenig ban <ip>
      erlkoenig unban <ip>
      erlkoenig counters
      erlkoenig status

  Runtime commands require a running erlkoenig node. The CLI connects
  via Erlang distribution (rpc:call), not a custom socket protocol.
  """

  @default_node :"erlkoenig@127.0.0.1"

  def main(args) do
    case args do
      # Local commands (no daemon)
      ["compile" | rest]   -> compile(rest)
      ["validate" | rest]  -> validate(rest)
      ["show" | rest]      -> show(rest)
      ["sign" | rest]      -> sign(rest)
      ["verify" | rest]    -> verify(rest)
      ["pki" | rest]       -> pki(rest)

      # Runtime commands (via Erlang distribution)
      ["ps" | _]           -> rpc_cmd(fn -> :erlkoenig.list() end, &render_ps/1)
      ["stop" | rest]      -> cmd_stop(rest)
      ["inspect" | rest]   -> cmd_inspect(rest)
      ["status" | _]       -> rpc_cmd(fn -> :erlkoenig_nft.status() end, &render_status/1)
      ["ban" | rest]       -> cmd_ban(rest)
      ["unban" | rest]     -> cmd_unban(rest)
      ["counters" | _]     -> rpc_cmd(fn -> :erlkoenig_nft.rates() end, &render_counters/1)
      ["guard", "stats"]   -> rpc_cmd(fn -> :erlkoenig_nft.guard_stats() end, &render_map/1)
      ["guard", "banned"]  -> rpc_cmd(fn -> :erlkoenig_nft.guard_banned() end, &render_list/1)

      ["--help" | _]       -> usage()
      ["-h" | _]           -> usage()
      ["--version" | _]    -> IO.puts("erlkoenig 0.4.0")
      _                    -> usage()
    end
  end

  # --- Compile / Validate / Show ---

  defp compile(args) do
    {opts, files, _} =
      OptionParser.parse(args, strict: [output: :string], aliases: [o: :output])

    case files do
      [input_file] -> do_compile(input_file, opts)
      _ -> error("Usage: erlkoenig compile <file.exs> [-o output.term]")
    end
  end

  defp validate(args) do
    case args do
      [input_file] -> do_validate(input_file)
      _ -> error("Usage: erlkoenig validate <file.exs>")
    end
  end

  defp show(args) do
    case args do
      [input_file] -> do_show(input_file)
      _ -> error("Usage: erlkoenig show <file.exs>")
    end
  end

  defp do_compile(input_file, opts) do
    check_file!(input_file)
    output_file = Keyword.get(opts, :output, Path.rootname(input_file) <> ".term")

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
    containers = if function_exported?(module, :containers, 0),
      do: module.containers(),
      else: error("Module #{inspect(module)} has no containers/0 function")

    errors = validate_containers(containers)
    case errors do
      [] -> info("OK - #{length(containers)} container(s), no errors")
      errs ->
        Enum.each(errs, fn e -> error_msg("  ERROR: #{e}") end)
        error("#{length(errs)} error(s) found")
    end
  end

  defp do_show(input_file) do
    check_file!(input_file)
    modules = Code.compile_file(input_file)

    Enum.each(modules, fn {mod, _} ->
      cond do
        function_exported?(mod, :config, 0) ->
          ErlkoenigNft.CLI.Formatter.render_firewall(mod.config(), mod)
        function_exported?(mod, :guard_config, 0) ->
          ErlkoenigNft.CLI.Formatter.render_guard(mod.guard_config(), mod)
        function_exported?(mod, :watches, 0) ->
          ErlkoenigNft.CLI.Formatter.render_watch(mod.watches(), mod)
        function_exported?(mod, :containers, 0) ->
          render_containers(mod.containers())
        true -> :skip
      end
    end)
  end

  # --- Runtime commands via rpc ---

  defp cmd_stop([id | _]) do
    rpc_cmd(fn ->
      case :erlkoenig.find_by_id(String.to_charlist(id)) do
        {:ok, pid} -> :erlkoenig.stop(pid)
        err -> err
      end
    end, fn
      :ok -> info("Stopped: #{id}")
      err -> error("Stop failed: #{inspect(err)}")
    end)
  end
  defp cmd_stop(_), do: error("Usage: erlkoenig stop <container-id>")

  defp cmd_inspect([id | _]) do
    rpc_cmd(fn ->
      case :erlkoenig.find_by_id(String.to_charlist(id)) do
        {:ok, pid} -> :erlkoenig.inspect(pid)
        err -> err
      end
    end, &render_map/1)
  end
  defp cmd_inspect(_), do: error("Usage: erlkoenig inspect <container-id>")

  defp cmd_ban([ip | _]) do
    rpc_cmd(fn -> :erlkoenig_nft.ban(String.to_charlist(ip)) end, fn
      :ok -> info("Banned: #{ip}")
      err -> error("Ban failed: #{inspect(err)}")
    end)
  end
  defp cmd_ban(_), do: error("Usage: erlkoenig ban <ip>")

  defp cmd_unban([ip | _]) do
    rpc_cmd(fn -> :erlkoenig_nft.unban(String.to_charlist(ip)) end, fn
      :ok -> info("Unbanned: #{ip}")
      err -> error("Unban failed: #{inspect(err)}")
    end)
  end
  defp cmd_unban(_), do: error("Usage: erlkoenig unban <ip>")

  defp rpc_cmd(fun, renderer) do
    node = get_node()
    ensure_distributed()

    case :rpc.call(node, :erlang, :apply, [fun, []]) do
      {:badrpc, :nodedown} ->
        error("Cannot connect to #{node}. Is erlkoenig running?")
      {:badrpc, reason} ->
        error("RPC failed: #{inspect(reason)}")
      result ->
        renderer.(result)
    end
  end

  defp ensure_distributed do
    case Node.alive?() do
      true -> :ok
      false ->
        name = :"erlkoenig_cli_#{:rand.uniform(999999)}@127.0.0.1"
        case :net_kernel.start(name, %{name_domain: :longnames}) do
          {:ok, _} ->
            cookie = get_cookie()
            if cookie, do: Node.set_cookie(cookie)
            :ok
          {:error, reason} ->
            error("Cannot start distribution: #{inspect(reason)}")
        end
    end
  end

  defp get_node do
    case System.get_env("ERLKOENIG_NODE") do
      nil -> @default_node
      name -> String.to_atom(name)
    end
  end

  defp get_cookie do
    case System.get_env("ERLKOENIG_COOKIE") do
      nil ->
        cookie_file = Path.expand("~/.erlang.cookie")
        if File.exists?(cookie_file) do
          cookie_file |> File.read!() |> String.trim() |> String.to_atom()
        else
          nil
        end
      cookie -> String.to_atom(cookie)
    end
  end

  # --- Renderers ---

  defp render_ps(containers) when is_list(containers) do
    case containers do
      [] -> info("(no containers)")
      _ ->
        IO.puts(pad("ID", 14) <> pad("NAME", 16) <> pad("STATE", 12) <>
                pad("IP", 16) <> "PID")
        Enum.each(containers, fn ct ->
          id = ct |> Map.get(:id, <<>>) |> binary_part(0, min(byte_size(Map.get(ct, :id, <<>>)), 12))
          name = Map.get(ct, :name, "-")
          state = Map.get(ct, :state, :unknown)
          ip = Map.get(ct, :net_info, %{}) |> Map.get(:ip, "-") |> format_ip()
          pid = Map.get(ct, :os_pid, "-")
          IO.puts(pad("#{id}", 14) <> pad("#{name}", 16) <> pad("#{state}", 12) <>
                  pad("#{ip}", 16) <> "#{pid}")
        end)
    end
  end
  defp render_ps(other), do: IO.puts(inspect(other))

  defp render_status(data) when is_map(data) do
    Enum.each(data, fn {k, v} -> IO.puts("#{k}: #{inspect(v)}") end)
  end
  defp render_status(other), do: IO.puts(inspect(other))

  defp render_counters(data) when is_map(data) do
    Enum.each(data, fn {name, rates} ->
      pps = Map.get(rates, :pps, 0.0)
      bps = Map.get(rates, :bps, 0.0)
      IO.puts("#{pad("#{name}", 20)} #{format_rate(pps)} pps  #{format_rate(bps)} bps")
    end)
  end
  defp render_counters(other), do: IO.puts(inspect(other))

  defp render_map(data) when is_map(data) do
    IO.puts(:io_lib.format(~c"~tp", [data]))
  end
  defp render_map(other), do: IO.puts(inspect(other))

  defp render_list(data) when is_list(data) do
    Enum.each(data, fn item -> IO.puts(inspect(item)) end)
  end
  defp render_list(other), do: IO.puts(inspect(other))

  defp render_containers(containers) do
    Enum.each(containers, fn ct ->
      name = Map.get(ct, :name, "?")
      binary = Map.get(ct, :binary, "?")
      ip = Map.get(ct, :ip, nil) |> format_ip()
      IO.puts("  #{pad("#{name}", 16)} #{pad("#{ip}", 16)} #{binary}")
    end)
  end

  # --- Sign / Verify / PKI (unchanged) ---

  defp sign(args) do
    {opts, files, _} =
      OptionParser.parse(args,
        strict: [cert: :string, key: :string, git_sha: :string, out: :string],
        aliases: [c: :cert, k: :key, o: :out])

    case files do
      [binary_path] ->
        cert = opts[:cert] || error("--cert is required")
        key = opts[:key] || error("--key is required")
        out = opts[:out] || binary_path <> ".sig"
        check_file!(binary_path)
        check_file!(cert)
        check_file!(key)

        case Erlkoenig.Sig.sign(binary_path, cert, key, %{git_sha: opts[:git_sha]}) do
          {:ok, sig_data} ->
            File.write!(out, sig_data)
            info("Signed: #{binary_path}")
            info("  Output:  #{out}")
            info("  SHA256:  #{sha256_file(binary_path)}")
          {:error, reason} -> error("Sign failed: #{inspect(reason)}")
        end
      _ -> error("Usage: erlkoenig sign <binary> --cert <cert.pem> --key <key.pem>")
    end
  end

  defp verify(args) do
    {opts, files, _} =
      OptionParser.parse(args,
        strict: [sig: :string, trust_root: :string],
        aliases: [s: :sig, t: :trust_root])

    case files do
      [binary_path] ->
        sig_path = opts[:sig] || binary_path <> ".sig"
        check_file!(binary_path)
        check_file!(sig_path)

        case Erlkoenig.Sig.verify(binary_path, sig_path) do
          {:ok, meta} ->
            info("Binary:    #{binary_path}")
            info("SHA256:    #{meta.sha256}")
            info("Signer:    #{meta.signer}")
            info("Signed at: #{format_timestamp(meta.timestamp)}")
            info("Chain:     #{length(meta.chain)} certificate(s)")
            info("Result:    OK")
          {:error, reason} -> error("Verification failed: #{inspect(reason)}")
        end
      _ -> error("Usage: erlkoenig verify <binary> [--sig <file.sig>]")
    end
  end

  defp pki(args) do
    case args do
      ["create-root-ca" | rest] -> pki_create(rest, &Erlkoenig.PKI.create_root_ca/1, "Root CA")
      ["create-sub-ca" | rest] -> pki_create(rest, &Erlkoenig.PKI.create_sub_ca/1, "Sub-CA")
      ["create-signing-cert" | rest] -> pki_create(rest, &Erlkoenig.PKI.create_signing_cert/1, "Signing cert")
      _ -> error("Usage: erlkoenig pki create-root-ca --cn <name> --out <cert.pem> --key-out <key.pem>")
    end
  end

  defp pki_create(args, fun, label) do
    {opts, _, _} =
      OptionParser.parse(args,
        strict: [cn: :string, out: :string, key_out: :string, validity: :string,
                 ca: :string, ca_key: :string])

    case fun.(opts) do
      {:ok, cert, key} ->
        info("#{label} created:")
        info("  Certificate: #{cert}")
        info("  Private key: #{key}")
      {:error, reason} -> error("Failed: #{inspect(reason)}")
    end
  end

  # --- Module loading ---

  defp find_dsl_module(input_file) do
    modules = Code.compile_file(input_file)
    case modules do
      [{mod, _}] -> mod
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
    check_duplicate_ips(containers) ++
    check_duplicate_ports(containers) ++
    Enum.flat_map(containers, &check_container_fields/1)
  end

  defp check_container_fields(%{name: name} = ct) do
    errs = []
    errs = if ct[:binary] == nil, do: errs ++ ["#{name}: missing binary path"], else: errs
    errs = if ct[:ip] == nil, do: errs ++ ["#{name}: missing IP address"], else: errs
    errs
  end

  defp check_duplicate_ips(containers) do
    for %{ip: ip, name: name} <- containers, ip != nil, do: {ip, name}
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.filter(fn {_ip, names} -> length(names) > 1 end)
    |> Enum.map(fn {ip, names} ->
      "duplicate IP #{inspect(ip)} in containers: #{Enum.join(names, ", ")}"
    end)
  end

  defp check_duplicate_ports(containers) do
    for %{name: name} = ct <- containers,
        {host_port, _} <- Map.get(ct, :ports, []),
        do: {host_port, name}
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.filter(fn {_port, names} -> length(names) > 1 end)
    |> Enum.map(fn {port, names} ->
      "duplicate host port #{port} in containers: #{Enum.join(names, ", ")}"
    end)
  end

  # --- Helpers ---

  defp sha256_file(path) do
    path |> File.read!() |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16(case: :lower)
  end

  defp format_timestamp(ts) do
    {{y, mo, d}, {h, mi, s}} = :calendar.gregorian_seconds_to_datetime(ts + 62_167_219_200)
    :io_lib.format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ", [y, mo, d, h, mi, s])
    |> to_string()
  end

  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_ip(nil), do: "-"
  defp format_ip(other), do: "#{other}"

  defp format_rate(r) when r >= 1_000_000, do: "#{Float.round(r / 1_000_000, 1)}M"
  defp format_rate(r) when r >= 1_000, do: "#{Float.round(r / 1_000, 1)}K"
  defp format_rate(r) when is_float(r), do: "#{Float.round(r, 1)}"
  defp format_rate(r), do: "#{r}"

  defp pad(str, width) do
    len = String.length(str)
    if len >= width, do: str <> " ", else: str <> String.duplicate(" ", width - len)
  end

  defp check_file!(path) do
    unless File.exists?(path), do: error("File not found: #{path}")
  end

  defp info(msg), do: IO.puts(msg)
  defp error_msg(msg), do: IO.puts(:stderr, msg)
  defp error(msg) do
    IO.puts(:stderr, msg)
    System.halt(1)
  end

  defp usage do
    IO.puts("""
    erlkoenig - Zero-trust container runtime

    Local commands (no daemon needed):
        compile <file.exs> [-o out.term]    Compile DSL to Erlang term file
        validate <file.exs>                 Check DSL for errors
        show <file.exs>                     Render firewall/container config
        sign <binary> --cert --key          Sign binary with Ed25519
        verify <binary>                     Verify binary signature
        pki create-root-ca ...              Create PKI certificates

    Runtime commands (via Erlang distribution):
        ps                                  List running containers
        stop <id>                           Stop a container
        inspect <id>                        Container details
        status                              Firewall status
        ban <ip>                            Ban IP address
        unban <ip>                           Unban IP address
        counters                            Show counter rates
        guard stats                         Threat detection stats
        guard banned                        List banned IPs

    Environment:
        ERLKOENIG_NODE      Target node (default: erlkoenig@127.0.0.1)
        ERLKOENIG_COOKIE    Erlang cookie (default: ~/.erlang.cookie)
    """)
    System.halt(1)
  end
end
