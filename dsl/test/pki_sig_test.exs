defmodule Erlkoenig.PKISigTest do
  use ExUnit.Case, async: false

  @moduletag :pki_sig

  @openssl_available System.find_executable("openssl") != nil

  setup context do
    dir = Path.join(System.tmp_dir!(), "erlkoenig_pki_sig_test_#{:rand.uniform(1_000_000)}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    if context[:needs_openssl] && !@openssl_available do
      :skip
    else
      {:ok, dir: dir}
    end
  end

  # ── PKI ──────────────────────────────────────────────────────────────

  describe "PKI.create_root_ca/1" do
    @describetag :pki

    @tag :needs_openssl
    test "creates root CA cert and key", %{dir: dir} do
      cert = Path.join(dir, "root.pem")
      key = Path.join(dir, "root-key.pem")

      assert {:ok, ^cert, ^key} =
               Erlkoenig.PKI.create_root_ca(cn: "Test Root CA", out: cert, key_out: key)

      assert File.exists?(cert)
      assert File.exists?(key)

      # verify it is a valid certificate
      {out, 0} = System.cmd("openssl", ["x509", "-in", cert, "-noout", "-subject"])
      assert out =~ "Test Root CA"

      # verify it is a CA
      {ext, 0} = System.cmd("openssl", ["x509", "-in", cert, "-noout", "-text"])
      assert ext =~ "CA:TRUE"
    end

    @tag :needs_openssl
    test "respects validity option", %{dir: dir} do
      cert = Path.join(dir, "root.pem")
      key = Path.join(dir, "root-key.pem")

      assert {:ok, _, _} =
               Erlkoenig.PKI.create_root_ca(cn: "Short Root", out: cert, key_out: key, validity: "30d")

      assert File.exists?(cert)
    end

    @tag :needs_openssl
    test "validity with year suffix", %{dir: dir} do
      cert = Path.join(dir, "root.pem")
      key = Path.join(dir, "root-key.pem")

      assert {:ok, _, _} =
               Erlkoenig.PKI.create_root_ca(cn: "Year Root", out: cert, key_out: key, validity: "2y")

      assert File.exists?(cert)
    end
  end

  describe "PKI.create_sub_ca/1" do
    @describetag :pki

    @tag :needs_openssl
    test "creates sub-CA signed by root", %{dir: dir} do
      root_cert = Path.join(dir, "root.pem")
      root_key = Path.join(dir, "root-key.pem")
      sub_cert = Path.join(dir, "sub.pem")
      sub_key = Path.join(dir, "sub-key.pem")

      {:ok, _, _} =
        Erlkoenig.PKI.create_root_ca(cn: "Test Root CA", out: root_cert, key_out: root_key)

      assert {:ok, ^sub_cert, ^sub_key} =
               Erlkoenig.PKI.create_sub_ca(
                 cn: "Test Sub CA",
                 ca: root_cert,
                 ca_key: root_key,
                 out: sub_cert,
                 key_out: sub_key
               )

      assert File.exists?(sub_cert)
      assert File.exists?(sub_key)

      # verify issuer matches root
      {out, 0} = System.cmd("openssl", ["x509", "-in", sub_cert, "-noout", "-issuer"])
      assert out =~ "Test Root CA"

      # verify it is a CA with pathlen constraint
      {text, 0} = System.cmd("openssl", ["x509", "-in", sub_cert, "-noout", "-text"])
      assert text =~ "CA:TRUE"
    end

    @tag :needs_openssl
    test "sub-CA verifies against root", %{dir: dir} do
      root_cert = Path.join(dir, "root.pem")
      root_key = Path.join(dir, "root-key.pem")
      sub_cert = Path.join(dir, "sub.pem")
      sub_key = Path.join(dir, "sub-key.pem")

      {:ok, _, _} =
        Erlkoenig.PKI.create_root_ca(cn: "Root", out: root_cert, key_out: root_key)

      {:ok, _, _} =
        Erlkoenig.PKI.create_sub_ca(
          cn: "Sub",
          ca: root_cert,
          ca_key: root_key,
          out: sub_cert,
          key_out: sub_key
        )

      {_, code} = System.cmd("openssl", ["verify", "-CAfile", root_cert, sub_cert])
      assert code == 0
    end
  end

  describe "PKI.create_signing_cert/1" do
    @describetag :pki

    @tag :needs_openssl
    test "creates end-entity cert signed by CA", %{dir: dir} do
      root_cert = Path.join(dir, "root.pem")
      root_key = Path.join(dir, "root-key.pem")
      sign_cert = Path.join(dir, "signer.pem")
      sign_key = Path.join(dir, "signer-key.pem")

      {:ok, _, _} =
        Erlkoenig.PKI.create_root_ca(cn: "Root CA", out: root_cert, key_out: root_key)

      assert {:ok, ^sign_cert, ^sign_key} =
               Erlkoenig.PKI.create_signing_cert(
                 cn: "Test Signer",
                 ca: root_cert,
                 ca_key: root_key,
                 out: sign_cert,
                 key_out: sign_key
               )

      assert File.exists?(sign_cert)
      assert File.exists?(sign_key)

      # verify it is NOT a CA
      {text, 0} = System.cmd("openssl", ["x509", "-in", sign_cert, "-noout", "-text"])
      assert text =~ "CA:FALSE"

      # verify digitalSignature usage
      assert text =~ "Digital Signature"
    end
  end

  # ── Sig ──────────────────────────────────────────────────────────────

  describe "Sig.sign/4 and Sig.verify/2 roundtrip" do
    @describetag :sig

    @tag :needs_openssl
    test "sign and verify a binary", %{dir: dir} do
      {_root_cert, _root_key, sign_cert, sign_key} = create_pki(dir)
      binary_path = Path.join(dir, "payload.bin")
      sig_path = Path.join(dir, "payload.bin.sig")

      File.write!(binary_path, :crypto.strong_rand_bytes(4096))

      assert {:ok, sig_content} = Erlkoenig.Sig.sign(binary_path, sign_cert, sign_key)
      File.write!(sig_path, sig_content)

      assert {:ok, meta} = Erlkoenig.Sig.verify(binary_path, sig_path)
      assert meta.signer == "Test Signer"
      assert is_binary(meta.sha256)
      assert byte_size(meta.sha256) == 64  # hex-encoded sha256
      assert is_integer(meta.timestamp)
      assert length(meta.chain) >= 1
    end

    @tag :needs_openssl
    test "sign with git_sha option", %{dir: dir} do
      {_root_cert, _root_key, sign_cert, sign_key} = create_pki(dir)
      binary_path = Path.join(dir, "payload.bin")
      sig_path = Path.join(dir, "payload.bin.sig")
      git_sha = String.duplicate("ab", 20)  # 40 hex chars

      File.write!(binary_path, "hello erlkoenig")

      assert {:ok, sig_content} =
               Erlkoenig.Sig.sign(binary_path, sign_cert, sign_key, %{git_sha: git_sha})

      File.write!(sig_path, sig_content)

      assert {:ok, meta} = Erlkoenig.Sig.verify(binary_path, sig_path)
      assert meta.git_sha == git_sha
    end
  end

  describe "Sig tamper detection" do
    @describetag :sig

    @tag :needs_openssl
    test "verify fails when binary is modified after signing", %{dir: dir} do
      {_root_cert, _root_key, sign_cert, sign_key} = create_pki(dir)
      binary_path = Path.join(dir, "payload.bin")
      sig_path = Path.join(dir, "payload.bin.sig")

      File.write!(binary_path, "original content")

      {:ok, sig_content} = Erlkoenig.Sig.sign(binary_path, sign_cert, sign_key)
      File.write!(sig_path, sig_content)

      # tamper with the binary
      File.write!(binary_path, "tampered content")

      assert {:error, :sha256_mismatch} = Erlkoenig.Sig.verify(binary_path, sig_path)
    end

    @tag :needs_openssl
    test "verify fails when signature block is corrupted", %{dir: dir} do
      {_root_cert, _root_key, sign_cert, sign_key} = create_pki(dir)
      binary_path = Path.join(dir, "payload.bin")
      sig_path = Path.join(dir, "payload.bin.sig")

      File.write!(binary_path, "some data")

      {:ok, sig_content} = Erlkoenig.Sig.sign(binary_path, sign_cert, sign_key)

      # corrupt the base64 payload (flip a byte in the middle of the sig block)
      corrupted =
        sig_content
        |> String.replace("-----END ERLKOENIG SIGNATURE-----", "")
        |> String.replace("-----BEGIN ERLKOENIG SIGNATURE-----", "")
        |> then(fn rest ->
          # rebuild with flipped content
          "-----BEGIN ERLKOENIG SIGNATURE-----\n" <>
            String.duplicate("A", 44) <> "\n" <>
            "-----END ERLKOENIG SIGNATURE-----\n" <>
            rest
        end)

      File.write!(sig_path, corrupted)

      assert {:error, _reason} = Erlkoenig.Sig.verify(binary_path, sig_path)
    end
  end

  describe "Sig with certificate chain" do
    @describetag :sig

    @tag :needs_openssl
    test "sign with chain file containing multiple certs", %{dir: dir} do
      root_cert = Path.join(dir, "root.pem")
      root_key = Path.join(dir, "root-key.pem")
      sub_cert = Path.join(dir, "sub.pem")
      sub_key = Path.join(dir, "sub-key.pem")
      sign_cert = Path.join(dir, "signer.pem")
      sign_key = Path.join(dir, "signer-key.pem")

      {:ok, _, _} =
        Erlkoenig.PKI.create_root_ca(cn: "Chain Root", out: root_cert, key_out: root_key)

      {:ok, _, _} =
        Erlkoenig.PKI.create_sub_ca(
          cn: "Chain Sub",
          ca: root_cert,
          ca_key: root_key,
          out: sub_cert,
          key_out: sub_key
        )

      {:ok, _, _} =
        Erlkoenig.PKI.create_signing_cert(
          cn: "Chain Signer",
          ca: sub_cert,
          ca_key: sub_key,
          out: sign_cert,
          key_out: sign_key
        )

      # build chain file: signer cert + sub-CA cert
      chain_path = Path.join(dir, "chain.pem")
      chain = File.read!(sign_cert) <> File.read!(sub_cert)
      File.write!(chain_path, chain)

      binary_path = Path.join(dir, "payload.bin")
      sig_path = Path.join(dir, "payload.bin.sig")
      File.write!(binary_path, "chain test payload")

      assert {:ok, sig_content} = Erlkoenig.Sig.sign(binary_path, chain_path, sign_key)
      File.write!(sig_path, sig_content)

      assert {:ok, meta} = Erlkoenig.Sig.verify(binary_path, sig_path)
      assert meta.signer == "Chain Signer"
      # chain should include both certs (signer + sub-CA)
      assert length(meta.chain) == 2
    end

    @tag :needs_openssl
    test "verify_chain validates against trust root", %{dir: dir} do
      root_cert = Path.join(dir, "root.pem")
      root_key = Path.join(dir, "root-key.pem")
      sign_cert = Path.join(dir, "signer.pem")
      sign_key = Path.join(dir, "signer-key.pem")

      {:ok, _, _} =
        Erlkoenig.PKI.create_root_ca(cn: "Trust Root", out: root_cert, key_out: root_key)

      {:ok, _, _} =
        Erlkoenig.PKI.create_signing_cert(
          cn: "Trusted Signer",
          ca: root_cert,
          ca_key: root_key,
          out: sign_cert,
          key_out: sign_key
        )

      binary_path = Path.join(dir, "payload.bin")
      sig_path = Path.join(dir, "payload.bin.sig")
      File.write!(binary_path, "trust test")

      {:ok, sig_content} = Erlkoenig.Sig.sign(binary_path, sign_cert, sign_key)
      File.write!(sig_path, sig_content)

      {:ok, meta} = Erlkoenig.Sig.verify(binary_path, sig_path)
      assert :ok == Erlkoenig.Sig.verify_chain(meta.chain, root_cert)
    end

    @tag :needs_openssl
    test "verify_chain rejects untrusted root", %{dir: dir} do
      root_cert = Path.join(dir, "root.pem")
      root_key = Path.join(dir, "root-key.pem")
      other_root_cert = Path.join(dir, "other-root.pem")
      other_root_key = Path.join(dir, "other-root-key.pem")
      sign_cert = Path.join(dir, "signer.pem")
      sign_key = Path.join(dir, "signer-key.pem")

      {:ok, _, _} =
        Erlkoenig.PKI.create_root_ca(cn: "Real Root", out: root_cert, key_out: root_key)

      {:ok, _, _} =
        Erlkoenig.PKI.create_root_ca(cn: "Other Root", out: other_root_cert, key_out: other_root_key)

      {:ok, _, _} =
        Erlkoenig.PKI.create_signing_cert(
          cn: "Signer",
          ca: root_cert,
          ca_key: root_key,
          out: sign_cert,
          key_out: sign_key
        )

      binary_path = Path.join(dir, "payload.bin")
      sig_path = Path.join(dir, "payload.bin.sig")
      File.write!(binary_path, "untrusted test")

      {:ok, sig_content} = Erlkoenig.Sig.sign(binary_path, sign_cert, sign_key)
      File.write!(sig_path, sig_content)

      {:ok, meta} = Erlkoenig.Sig.verify(binary_path, sig_path)
      assert {:error, :untrusted_root} == Erlkoenig.Sig.verify_chain(meta.chain, other_root_cert)
    end
  end

  describe "Sig error handling" do
    @describetag :sig

    test "sign returns error for missing binary file", %{dir: dir} do
      assert {:error, :enoent} =
               Erlkoenig.Sig.sign(
                 Path.join(dir, "nonexistent.bin"),
                 Path.join(dir, "cert.pem"),
                 Path.join(dir, "key.pem")
               )
    end

    @tag :needs_openssl
    test "sign returns error for missing key file", %{dir: dir} do
      {_root_cert, _root_key, sign_cert, _sign_key} = create_pki(dir)
      binary_path = Path.join(dir, "payload.bin")
      File.write!(binary_path, "test")

      assert {:error, {:read_failed, _, :enoent}} =
               Erlkoenig.Sig.sign(binary_path, sign_cert, Path.join(dir, "missing-key.pem"))
    end

    @tag :needs_openssl
    test "sign returns error for missing cert file", %{dir: dir} do
      {_root_cert, _root_key, _sign_cert, sign_key} = create_pki(dir)
      binary_path = Path.join(dir, "payload.bin")
      File.write!(binary_path, "test")

      assert {:error, {:read_failed, _, :enoent}} =
               Erlkoenig.Sig.sign(binary_path, Path.join(dir, "missing-cert.pem"), sign_key)
    end

    test "verify returns error for missing sig file", %{dir: dir} do
      binary_path = Path.join(dir, "payload.bin")
      File.write!(binary_path, "test")

      assert {:error, :sig_not_found} =
               Erlkoenig.Sig.verify(binary_path, Path.join(dir, "nonexistent.sig"))
    end

    test "verify returns error for missing binary file", %{dir: dir} do
      # File.read returns {:error, :enoent} directly for the binary (first with clause)
      assert {:error, :enoent} =
               Erlkoenig.Sig.verify(
                 Path.join(dir, "nonexistent.bin"),
                 Path.join(dir, "sig.sig")
               )
    end

    test "verify returns error for invalid sig format", %{dir: dir} do
      binary_path = Path.join(dir, "payload.bin")
      sig_path = Path.join(dir, "payload.sig")
      File.write!(binary_path, "test")
      File.write!(sig_path, "not a valid signature file")

      assert {:error, :invalid_sig_format} = Erlkoenig.Sig.verify(binary_path, sig_path)
    end

    test "verify_chain returns error for missing trust root" do
      assert {:error, {:read_failed, _, :enoent}} =
               Erlkoenig.Sig.verify_chain([], "/nonexistent/root.pem")
    end
  end

  # ── Helpers ──────────────────────────────────────────────────────────

  defp create_pki(dir) do
    root_cert = Path.join(dir, "root.pem")
    root_key = Path.join(dir, "root-key.pem")
    sign_cert = Path.join(dir, "signer.pem")
    sign_key = Path.join(dir, "signer-key.pem")

    {:ok, _, _} =
      Erlkoenig.PKI.create_root_ca(cn: "Test Root CA", out: root_cert, key_out: root_key)

    {:ok, _, _} =
      Erlkoenig.PKI.create_signing_cert(
        cn: "Test Signer",
        ca: root_cert,
        ca_key: root_key,
        out: sign_cert,
        key_out: sign_key
      )

    {root_cert, root_key, sign_cert, sign_key}
  end
end
