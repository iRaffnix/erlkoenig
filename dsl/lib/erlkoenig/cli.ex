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
      commands="compile validate sign verify pki"

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
          'sign:Sign a static binary with Ed25519'
          'verify:Verify a binary signature and certificate chain'
          'pki:Create certificates (root-ca, sub-ca, signing-cert)'
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
      ["deploy" | rest]   -> deploy(rest)
      ["compile" | rest]  -> compile(rest)
      ["validate" | rest] -> validate(rest)
      ["sign" | rest]     -> sign(rest)
      ["verify" | rest]   -> verify(rest)
      ["pki" | rest]      -> pki(rest)
      ["spawn" | rest]    -> ctl_spawn(rest)
      ["stop" | rest]     -> ctl_stop(rest)
      ["ps" | _]          -> ctl_ps()
      ["inspect" | rest]  -> ctl_inspect(rest)
      ["audit" | rest]    -> ctl_audit(rest)
      ["status" | _]      -> ctl_status()
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

  # --- Sign ---

  defp sign(args) do
    {opts, files, _} =
      OptionParser.parse(args,
        strict: [cert: :string, key: :string, git_sha: :string, out: :string],
        aliases: [c: :cert, k: :key, o: :out]
      )

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
            info("  Output:    #{out}")
            info("  SHA256:    #{sha256_file(binary_path)}")
            if opts[:git_sha], do: info("  Git SHA:   #{opts[:git_sha]}")

          {:error, reason} ->
            error("Sign failed: #{inspect(reason)}")
        end

      _ ->
        error("Usage: erlkoenig sign <binary> --cert <cert.pem> --key <key.pem> [--git-sha <sha>] [-o output.sig]")
    end
  end

  # --- Verify ---

  defp verify(args) do
    {opts, files, _} =
      OptionParser.parse(args,
        strict: [sig: :string, trust_root: :string],
        aliases: [s: :sig, t: :trust_root]
      )

    case files do
      [binary_path] ->
        sig_path = opts[:sig] || binary_path <> ".sig"
        check_file!(binary_path)
        check_file!(sig_path)

        case Erlkoenig.Sig.verify(binary_path, sig_path) do
          {:ok, meta} ->
            info("Binary:    #{binary_path}")
            info("SHA256:    #{meta.sha256}")
            info("Git SHA:   #{meta.git_sha}")
            info("Signer:    #{meta.signer}")
            info("Signed at: #{format_timestamp(meta.timestamp)}")
            info("Chain:     #{length(meta.chain)} certificate(s)")

            if trust_root = opts[:trust_root] do
              check_file!(trust_root)

              case Erlkoenig.Sig.verify_chain(meta.chain, trust_root) do
                :ok -> info("Trust:     OK (chains to #{trust_root})")
                {:error, reason} -> error("Trust:     FAILED — #{inspect(reason)}")
              end
            end

            info("Result:    OK")

          {:error, reason} ->
            error("Verification failed: #{inspect(reason)}")
        end

      _ ->
        error("Usage: erlkoenig verify <binary> [--sig <file.sig>] [--trust-root <ca.pem>]")
    end
  end

  # --- PKI ---

  defp pki(args) do
    case args do
      ["create-root-ca" | rest] -> pki_create_root_ca(rest)
      ["create-sub-ca" | rest] -> pki_create_sub_ca(rest)
      ["create-signing-cert" | rest] -> pki_create_signing_cert(rest)
      _ -> error("""
        Usage:
          erlkoenig pki create-root-ca --cn <name> --out <cert.pem> --key-out <key.pem> [--validity 10y]
          erlkoenig pki create-sub-ca --cn <name> --ca <ca.pem> --ca-key <ca.key> --out <cert.pem> --key-out <key.pem>
          erlkoenig pki create-signing-cert --cn <name> --ca <ca.pem> --ca-key <ca.key> --out <cert.pem> --key-out <key.pem>
        """)
    end
  end

  defp pki_create_root_ca(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        strict: [cn: :string, out: :string, key_out: :string, validity: :string])

    case Erlkoenig.PKI.create_root_ca(opts) do
      {:ok, cert, key} ->
        info("Root CA created:")
        info("  Certificate: #{cert}")
        info("  Private key: #{key}")
      {:error, reason} ->
        error("Failed: #{inspect(reason)}")
    end
  end

  defp pki_create_sub_ca(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        strict: [cn: :string, ca: :string, ca_key: :string, out: :string, key_out: :string, validity: :string])

    case Erlkoenig.PKI.create_sub_ca(opts) do
      {:ok, cert, key} ->
        info("Sub-CA created:")
        info("  Certificate: #{cert}")
        info("  Private key: #{key}")
      {:error, reason} ->
        error("Failed: #{inspect(reason)}")
    end
  end

  defp pki_create_signing_cert(args) do
    {opts, _, _} =
      OptionParser.parse(args,
        strict: [cn: :string, ca: :string, ca_key: :string, out: :string, key_out: :string, validity: :string])

    case Erlkoenig.PKI.create_signing_cert(opts) do
      {:ok, cert, key} ->
        info("Signing certificate created:")
        info("  Certificate: #{cert}")
        info("  Private key: #{key}")
      {:error, reason} ->
        error("Failed: #{inspect(reason)}")
    end
  end

  defp sha256_file(path) do
    path |> File.read!() |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16(case: :lower)
  end

  defp format_timestamp(ts) do
    {{y, mo, d}, {h, mi, s}} = :calendar.gregorian_seconds_to_datetime(ts + 62_167_219_200)
    :io_lib.format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ", [y, mo, d, h, mi, s])
    |> to_string()
  end

  defp check_file!(path) do
    unless File.exists?(path) do
      error("File not found: #{path}")
    end
  end

  # --- Deploy ---

  defp deploy(args) do
    case args do
      [input_file] -> do_deploy(input_file)
      _ -> error("Usage: erlkoenig deploy <stack.exs>")
    end
  end

  defp do_deploy(input_file) do
    check_file!(input_file)
    info("Compiling #{input_file} ...")

    mod = find_dsl_module(input_file)
    spawn_list = mod.spawn_opts()

    info("  #{length(spawn_list)} container(s) found")
    info("")

    # Deploy in order (last defined = probably depends on earlier ones, so reverse)
    results = Enum.map(Enum.reverse(spawn_list), fn {name, binary, opts} ->
      deploy_one(name, binary, opts)
    end)

    ok_count = Enum.count(results, &match?(:ok, &1))
    fail_count = Enum.count(results, &match?({:error, _}, &1))

    info("")
    if fail_count == 0 do
      info("#{ok_count}/#{length(spawn_list)} containers running.")
    else
      error_msg("#{ok_count} started, #{fail_count} failed.")
      System.halt(1)
    end
  end

  defp deploy_one(name, binary, opts) do
    info("Deploying #{name} (#{format_ip(opts[:ip])}) ...")

    # Build spawn JSON
    opts_map = %{}
    opts_map = if opts[:ip], do: Map.put(opts_map, "ip", format_ip(opts[:ip])), else: opts_map
    opts_map = if opts[:args], do: Map.put(opts_map, "args", opts[:args]), else: opts_map
    opts_map = if opts[:signature_required], do: Map.put(opts_map, "signature", "required"), else: opts_map
    json = encode_simple_json(opts_map)

    case Erlkoenig.Ctl.spawn_container(binary, json) do
      {:ok, resp} ->
        info("  Started: #{name} (#{resp})")
        # Brief pause for container to initialize
        Process.sleep(1000)
        :ok
      {:error, msg} ->
        error_msg("  Failed: #{name} — #{msg}")
        {:error, msg}
    end
  end

  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp format_ip(nil), do: "auto"
  defp format_ip(other), do: "#{other}"

  # --- Control socket commands ---

  defp ctl_spawn(args) do
    {opts, files, _} =
      OptionParser.parse(args,
        strict: [ip: :string, args: :string, limits: :string,
                 firewall: :string, seccomp: :string, signature: :string])

    case files do
      [binary_path] ->
        opts_map = %{}
        opts_map = if opts[:ip], do: Map.put(opts_map, "ip", opts[:ip]), else: opts_map
        opts_map = if opts[:args], do: Map.put(opts_map, "args", String.split(opts[:args], ",")), else: opts_map
        opts_map = if opts[:signature], do: Map.put(opts_map, "signature", opts[:signature]), else: opts_map
        # Simple JSON encoding (no dependency needed for flat maps)
        json = encode_simple_json(opts_map)

        case Erlkoenig.Ctl.spawn_container(binary_path, json) do
          {:ok, resp} -> info("Started: #{resp}")
          {:error, msg} -> error("Spawn failed: #{msg}")
        end

      _ ->
        error("Usage: erlkoenig spawn <binary> --ip <addr> [--args <a,b,c>]")
    end
  end

  defp ctl_stop(args) do
    case args do
      [container_id] ->
        case Erlkoenig.Ctl.stop_container(container_id) do
          {:ok, _} -> info("Stopped: #{container_id}")
          {:error, msg} -> error("Stop failed: #{msg}")
        end
      _ ->
        error("Usage: erlkoenig stop <container-id>")
    end
  end

  defp ctl_ps do
    case Erlkoenig.Ctl.ps() do
      {:ok, data} ->
        if byte_size(data) > 0, do: IO.puts(data), else: info("(no containers)")
      {:error, msg} -> error("ps failed: #{msg}")
    end
  end

  defp ctl_inspect(args) do
    case args do
      [container_id] ->
        case Erlkoenig.Ctl.inspect_container(container_id) do
          {:ok, data} -> IO.puts(data)
          {:error, msg} -> error("Inspect failed: #{msg}")
        end
      _ ->
        error("Usage: erlkoenig inspect <container-id>")
    end
  end

  defp ctl_audit(args) do
    {opts, _, _} =
      OptionParser.parse(args, strict: [type: :string, since: :string, limit: :integer])

    json = encode_simple_json(Map.new(opts, fn {k, v} -> {to_string(k), v} end))

    case Erlkoenig.Ctl.audit(json) do
      {:ok, data} ->
        if byte_size(data) > 0, do: IO.puts(data), else: info("(no events)")
      {:error, msg} -> error("Audit failed: #{msg}")
    end
  end

  defp ctl_status do
    case Erlkoenig.Ctl.status() do
      {:ok, data} -> IO.puts(data)
      {:error, msg} -> error("Status failed: #{msg}")
    end
  end

  defp encode_simple_json(map) when map_size(map) == 0, do: "{}"
  defp encode_simple_json(map) do
    pairs = Enum.map(map, fn {k, v} ->
      "\"#{k}\":#{encode_json_value(v)}"
    end)
    "{" <> Enum.join(pairs, ",") <> "}"
  end

  defp encode_json_value(v) when is_binary(v), do: "\"#{v}\""
  defp encode_json_value(v) when is_integer(v), do: Integer.to_string(v)
  defp encode_json_value(v) when is_list(v) do
    items = Enum.map(v, &encode_json_value/1)
    "[" <> Enum.join(items, ",") <> "]"
  end
  defp encode_json_value(v), do: "\"#{v}\""

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
        erlkoenig deploy <stack.exs>
        erlkoenig spawn <binary> --ip <addr> [--args <a,b>]
        erlkoenig ps
        erlkoenig stop <container-id>
        erlkoenig inspect <container-id>
        erlkoenig status
        erlkoenig audit [--type <event-type>]
        erlkoenig compile <file.exs> [-o output.term]
        erlkoenig sign <binary> --cert <cert.pem> --key <key.pem>
        erlkoenig verify <binary> [--trust-root <ca.pem>]
        erlkoenig pki create-root-ca --cn <name> --out <cert.pem> --key-out <key.pem>
        erlkoenig --help

    Container management (via Unix socket):
        deploy      Deploy all containers from a stack.exs file
        spawn       Start a single container
        ps          List running containers
        stop        Stop a container
        inspect     Show container details
        status      Show daemon status
        audit       Query audit log

    Build & Security:
        compile     Compile a DSL .exs file to an Erlang .term file
        validate    Check a DSL .exs file for errors
        sign        Sign a static binary with Ed25519
        verify      Verify a binary signature and certificate chain
        pki         Create certificates for testing

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
