#
# PKI helper — generate test certificates via OpenSSL CLI.
#
# For production, customers use their own CA infrastructure.
# These helpers are convenience wrappers for testing and development.
#

defmodule Erlkoenig.PKI do
  @doc "Generate a self-signed Root CA."
  def create_root_ca(opts) do
    cn = Keyword.fetch!(opts, :cn)
    out = Keyword.fetch!(opts, :out)
    key_out = Keyword.fetch!(opts, :key_out)
    validity = Keyword.get(opts, :validity, "3650")

    days = parse_validity(validity)

    with :ok <- run_openssl(["genpkey", "-algorithm", "ed25519", "-out", key_out]),
         :ok <-
           run_openssl([
             "req", "-new", "-x509", "-key", key_out, "-out", out,
             "-days", to_string(days), "-subj", "/CN=#{cn}",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"
           ]) do
      {:ok, out, key_out}
    end
  end

  @doc "Generate a Sub-CA signed by a parent CA."
  def create_sub_ca(opts) do
    cn = Keyword.fetch!(opts, :cn)
    ca = Keyword.fetch!(opts, :ca)
    ca_key = Keyword.fetch!(opts, :ca_key)
    out = Keyword.fetch!(opts, :out)
    key_out = Keyword.fetch!(opts, :key_out)
    validity = Keyword.get(opts, :validity, "3650")

    days = parse_validity(validity)
    csr = out <> ".csr"

    with :ok <- run_openssl(["genpkey", "-algorithm", "ed25519", "-out", key_out]),
         :ok <- run_openssl(["req", "-new", "-key", key_out, "-out", csr, "-subj", "/CN=#{cn}"]),
         :ok <-
           run_openssl([
             "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
             "-CAcreateserial", "-out", out, "-days", to_string(days),
             "-extfile", extfile("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign")
           ]) do
      File.rm(csr)
      File.rm(ca <> ".srl")
      {:ok, out, key_out}
    end
  end

  @doc "Generate a signing certificate signed by a CA."
  def create_signing_cert(opts) do
    cn = Keyword.fetch!(opts, :cn)
    ca = Keyword.fetch!(opts, :ca)
    ca_key = Keyword.fetch!(opts, :ca_key)
    out = Keyword.fetch!(opts, :out)
    key_out = Keyword.fetch!(opts, :key_out)
    validity = Keyword.get(opts, :validity, "90")

    days = parse_validity(validity)
    csr = out <> ".csr"

    with :ok <- run_openssl(["genpkey", "-algorithm", "ed25519", "-out", key_out]),
         :ok <- run_openssl(["req", "-new", "-key", key_out, "-out", csr, "-subj", "/CN=#{cn}"]),
         :ok <-
           run_openssl([
             "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
             "-CAcreateserial", "-out", out, "-days", to_string(days),
             "-extfile", extfile("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature")
           ]) do
      File.rm(csr)
      File.rm(ca <> ".srl")
      {:ok, out, key_out}
    end
  end

  # --- Helpers ---

  defp run_openssl(args) do
    case System.cmd("openssl", args, stderr_to_stdout: true) do
      {_, 0} -> :ok
      {output, code} -> {:error, {:openssl_failed, code, output}}
    end
  end

  defp extfile(content) do
    path = Path.join(System.tmp_dir!(), "erlkoenig_pki_ext_#{:rand.uniform(1_000_000)}")
    File.write!(path, content)
    path
  end

  defp parse_validity(v) when is_integer(v), do: v
  defp parse_validity(v) when is_binary(v) do
    cond do
      String.ends_with?(v, "y") -> String.trim_trailing(v, "y") |> String.to_integer() |> Kernel.*(365)
      String.ends_with?(v, "d") -> String.trim_trailing(v, "d") |> String.to_integer()
      true -> String.to_integer(v)
    end
  end
end
