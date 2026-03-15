#
# Binary signature creation and verification for the CLI.
#
# Mirrors the Erlang erlkoenig_sig module — same payload format,
# same .sig file structure. Can be used standalone (no OTP release).
#

defmodule Erlkoenig.Sig do
  @version 1
  @alg_ed25519 1

  @doc "Sign a binary file. Returns {:ok, sig_file_content} or {:error, reason}."
  def sign(binary_path, cert_path, key_path, opts \\ %{}) do
    with {:ok, binary_data} <- File.read(binary_path),
         {:ok, key_der} <- read_private_key(key_path),
         {:ok, certs} <- read_cert_chain(cert_path) do
      sha256 = :crypto.hash(:sha256, binary_data)
      git_sha = parse_git_sha(opts[:git_sha] || "")
      timestamp = System.os_time(:second)
      signer_cn = extract_cn(hd(certs))

      payload =
        <<@version::8, @alg_ed25519::8, sha256::binary-32, git_sha::binary-20,
          timestamp::big-64, byte_size(signer_cn)::big-16, signer_cn::binary>>

      signature = :crypto.sign(:eddsa, :none, payload, [key_der, :ed25519])

      sig_block = encode_sig_block(payload, signature)

      cert_pems =
        Enum.map(certs, fn der ->
          :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
        end)

      {:ok, IO.iodata_to_binary([sig_block | cert_pems])}
    end
  end

  @doc "Verify a binary against its .sig file. Returns {:ok, meta} or {:error, reason}."
  def verify(binary_path, sig_path) do
    with {:ok, binary_data} <- File.read(binary_path),
         {:ok, sig_data} <- read_sig_file(sig_path),
         {:ok, payload, signature, certs} <- parse_sig_file(sig_data),
         {:ok, meta} <- decode_payload(payload) do
      actual_sha = :crypto.hash(:sha256, binary_data)

      cond do
        meta.sha256 != actual_sha ->
          {:error, :sha256_mismatch}

        not verify_ed25519(payload, signature, hd(certs)) ->
          {:error, :signature_invalid}

        true ->
          {:ok,
           %{
             sha256: hex(meta.sha256),
             git_sha: hex(meta.git_sha),
             signer: meta.signer_cn,
             timestamp: meta.timestamp,
             chain: certs
           }}
      end
    end
  end

  @doc "Verify a certificate chain against a trust root."
  def verify_chain(cert_chain, trust_root_path) do
    case File.read(trust_root_path) do
      {:ok, pem} ->
        roots =
          for {:Certificate, der, _} <- :public_key.pem_decode(pem), do: der

        try_roots(cert_chain, roots)

      {:error, reason} ->
        {:error, {:read_failed, trust_root_path, reason}}
    end
  end

  # --- Private ---

  defp try_roots(_chain, []), do: {:error, :untrusted_root}

  defp try_roots(chain, [root | rest]) do
    root_cert = :public_key.pkix_decode_cert(root, :otp)
    path_certs = Enum.map(Enum.reverse(chain), &:public_key.pkix_decode_cert(&1, :otp))

    case :public_key.pkix_path_validation(root_cert, path_certs, []) do
      {:ok, _} -> :ok
      {:error, _} -> try_roots(chain, rest)
    end
  end

  defp verify_ed25519(payload, signature, der_cert) do
    cert = :public_key.pkix_decode_cert(der_cert, :plain)
    tbs = elem(cert, 1)
    spki = elem(tbs, 7)  # SubjectPublicKeyInfo
    pub_key = elem(spki, 2)  # subjectPublicKey bitstring
    :crypto.verify(:eddsa, :none, payload, signature, [pub_key, :ed25519])
  end

  defp read_private_key(path) do
    case File.read(path) do
      {:ok, pem} ->
        [{_, der, :not_encrypted}] = :public_key.pem_decode(pem)
        # Ed25519 PKCS#8: find raw key after OID 1.3.101.112
        oid = <<0x06, 0x03, 0x2B, 0x65, 0x70>>

        case :binary.match(der, oid) do
          {pos, 5} ->
            rest = :binary.part(der, pos + 5, byte_size(der) - pos - 5)

            case rest do
              <<0x04, _, 0x04, 0x20, key::binary-32, _::binary>> -> {:ok, key}
              _ -> {:error, :ed25519_key_extraction_failed}
            end

          :nomatch ->
            {:error, :not_ed25519_key}
        end

      {:error, reason} ->
        {:error, {:read_failed, path, reason}}
    end
  end

  defp read_cert_chain(path) do
    case File.read(path) do
      {:ok, pem} ->
        certs = for {:Certificate, der, _} <- :public_key.pem_decode(pem), do: der

        case certs do
          [] -> {:error, {:no_certificates, path}}
          _ -> {:ok, certs}
        end

      {:error, reason} ->
        {:error, {:read_failed, path, reason}}
    end
  end

  defp read_sig_file(path) do
    case File.read(path) do
      {:ok, _} = ok -> ok
      {:error, :enoent} -> {:error, :sig_not_found}
      {:error, reason} -> {:error, {:read_failed, path, reason}}
    end
  end

  defp parse_sig_file(bin) do
    begin_marker = "-----BEGIN ERLKOENIG SIGNATURE-----"
    end_marker = "-----END ERLKOENIG SIGNATURE-----"

    with {s1, l1} <- :binary.match(bin, begin_marker),
         after_begin = s1 + l1,
         {s2, l2} <-
           :binary.match(bin, end_marker, scope: {after_begin, byte_size(bin) - after_begin}) do
      sig_b64 = :binary.part(bin, after_begin, s2 - after_begin) |> strip_ws()
      cert_pem = :binary.part(bin, s2 + l2, byte_size(bin) - s2 - l2)

      <<payload_len::big-32, rest::binary>> = Base.decode64!(sig_b64)
      <<payload::binary-size(payload_len), signature::binary>> = rest

      certs = for {:Certificate, der, _} <- :public_key.pem_decode(cert_pem), do: der

      case certs do
        [] -> {:error, :no_certificates_in_sig}
        _ -> {:ok, payload, signature, certs}
      end
    else
      :nomatch -> {:error, :invalid_sig_format}
    end
  end

  defp decode_payload(
         <<@version::8, @alg_ed25519::8, sha256::binary-32, git_sha::binary-20,
           ts::big-64, cn_len::big-16, cn::binary-size(cn_len)>>
       ) do
    {:ok, %{sha256: sha256, git_sha: git_sha, timestamp: ts, signer_cn: cn}}
  end

  defp decode_payload(_), do: {:error, :invalid_payload}

  defp encode_sig_block(payload, signature) do
    inner = <<byte_size(payload)::big-32, payload::binary, signature::binary>>
    b64 = Base.encode64(inner)
    lines = wrap_b64(b64)

    [
      "-----BEGIN ERLKOENIG SIGNATURE-----\n",
      Enum.intersperse(lines, "\n"),
      "\n-----END ERLKOENIG SIGNATURE-----\n"
    ]
  end

  defp wrap_b64(<<>>), do: []
  defp wrap_b64(<<line::binary-64, rest::binary>>), do: [line | wrap_b64(rest)]
  defp wrap_b64(rest), do: [rest]

  defp extract_cn(der_cert) do
    # Use :plain decoding → #'Certificate' record
    # Record layout: {Certificate, TBSCertificate, ...}
    # TBSCertificate: {TBSCertificate, version, serial, signature, issuer, validity, subject, ...}
    cert = :public_key.pkix_decode_cert(der_cert, :plain)
    tbs = elem(cert, 1)
    subject = elem(tbs, 6)  # subject rdnSequence
    {:rdnSequence, rdns} = subject

    Enum.find_value(List.flatten(rdns), "unknown", fn
      {:AttributeTypeAndValue, {2, 5, 4, 3}, value} ->
        case value do
          {:utf8String, s} -> s
          {:printableString, s} -> to_string(s)
          s when is_binary(s) -> s
          s when is_list(s) -> to_string(s)
          _ -> nil
        end

      _ ->
        nil
    end)
  end

  defp parse_git_sha(""), do: <<0::160>>
  defp parse_git_sha(hex) when byte_size(hex) == 40, do: Base.decode16!(hex, case: :mixed)
  defp parse_git_sha(raw) when byte_size(raw) == 20, do: raw
  defp parse_git_sha(_), do: <<0::160>>

  defp hex(bin), do: Base.encode16(bin, case: :lower)
  defp strip_ws(bin), do: for(<<c <- bin>>, c not in ~c"\n\r\s\t", into: <<>>, do: <<c>>)
end
