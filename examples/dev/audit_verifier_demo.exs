# examples/dev/audit_verifier_demo.exs
#
# Runnable end-to-end demo for SPEC-AS-005 stage 4 — the offline
# Go audit verifier. Mirrors Chapter 20 of the book in a single
# `mix run` call.
#
# What it does, in order:
#   1. Sanity: dist/audit-verifier exists. If not, print how to build.
#   2. Wires the Erlang ebins into the VM, sets a /tmp sandbox.
#   3. Generates Ed25519 + HMAC keys, starts the audit gen_server.
#   4. Logs two events, seals the day.
#   5. Runs all four verification modes (chain, chain+sig, seal,
#      verify-day combined) and asserts each exits 0.
#   6. Runs three tamper exercises:
#        - byte tamper      → exit 1
#        - wrong pubkey     → exit 2
#        - wrong HMAC key   → exit 3
#   7. Prints a per-scenario PASS/FAIL summary, exits 0 on full
#      success, 1 if any scenario produced an unexpected code.
#
# Usage (from the dsl/ directory):
#
#     cd dsl
#     mix run ../examples/dev/audit_verifier_demo.exs
#
# Prerequisite once: `make erl && make verifier` from the repo root.

# --- 1. Locate the verifier binary ---

repo_root = Path.expand("../..", __DIR__)
verifier  = Path.join(repo_root, "dist/audit-verifier")

unless File.exists?(verifier) do
  IO.puts(:stderr, """
  No audit-verifier binary at #{verifier}.
    Build it first:    make verifier
  """)
  System.halt(1)
end

# --- 2. Pull in the Erlang ebins ---

repo_root
|> Path.join("_build/default/lib/*/ebin")
|> Path.wildcard()
|> Enum.each(&:code.add_pathz(String.to_charlist(&1)))

# Tutorial-friendly logging (the audit gen_server's startup line is
# fine but the rest is noise for this demo).
:logger.set_primary_config(:level, :warning)

# --- 3. Sandbox + keys ---

sandbox =
  "/tmp/ek-verifier-demo-#{System.system_time(:microsecond)}-#{System.unique_integer([:positive])}"

File.mkdir_p!(sandbox)

audit_path     = Path.join(sandbox, "audit.jsonl")
sign_priv_path = Path.join(sandbox, "sign.key")
sign_pub_path  = Path.join(sandbox, "sign.pub")
hmac_path      = Path.join(sandbox, "hmac.key")
wrong_pub_path = Path.join(sandbox, "wrong.pub")
wrong_hmac_path = Path.join(sandbox, "wrong.hmac")
tampered_path  = Path.join(sandbox, "tampered.sealed")

{pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
{wrong_pub, _} = :crypto.generate_key(:eddsa, :ed25519)
File.write!(sign_priv_path, priv)
File.write!(sign_pub_path,  pub)
File.write!(wrong_pub_path, wrong_pub)
File.write!(hmac_path,       :crypto.strong_rand_bytes(32))
File.write!(wrong_hmac_path, :crypto.strong_rand_bytes(32))

IO.puts("\n=== sandbox ===")
IO.puts("dir:         #{sandbox}")
IO.puts("audit:       #{audit_path}")

# --- 4. Start audit gen_server, log events, seal the day ---

:application.set_env(:erlkoenig, :audit_path,        String.to_charlist(audit_path))
:application.set_env(:erlkoenig, :audit_signing_key, String.to_charlist(sign_priv_path))
:application.set_env(:erlkoenig, :audit_hmac_key,    String.to_charlist(hmac_path))

{:ok, audit_pid} = :erlkoenig_audit.start_link()

:erlkoenig_audit.log(%{type: :morning, subject: "task1", result: :ok})
:erlkoenig_audit.log(%{type: :morning, subject: "task2", result: :ok})
Process.sleep(150)

{:ok, info} = :erlkoenig_audit.seal_day()
sealed = info[:sealed_path] |> List.to_string()
IO.puts("sealed:      #{sealed}")

# Now stop the audit gen_server — the verifier reads the file
# offline; nothing erlkoenig-side should still be writing to it.
GenServer.stop(audit_pid)

# --- 5. Verification scenarios ---
#
# Each scenario gets a name, the verifier args, and the EXPECTED
# exit code. The demo runs them all, prints a PASS/FAIL line per
# scenario, then exits 0 only if everything matched expectation.

run = fn args ->
  {out, exit_code} =
    System.cmd(verifier, args, stderr_to_stdout: true)
  {String.trim(out), exit_code}
end

results =
  for {name, args, expected} <- [
        {"chain only (no key)",
         ["verify-chain", sealed], 0},
        {"chain + signatures",
         ["verify-chain", "--pubkey", sign_pub_path, sealed], 0},
        {"seal HMAC",
         ["verify-seal", "--hmac-key", hmac_path, sealed], 0},
        {"verify-day (combined)",
         ["verify-day",
          "--pubkey",   sign_pub_path,
          "--hmac-key", hmac_path,
          sealed], 0}
      ] do
    {out, code} = run.(args)
    pass? = code == expected
    {name, expected, code, pass?, out}
  end

# --- 6. Tamper exercises ---

# 6a. Byte tamper -> exit 1.
File.cp!(sealed, tampered_path)
File.chmod!(tampered_path, 0o644)
File.write!(tampered_path,
  String.replace(File.read!(tampered_path), "task1", "TASK1"))

tamper_results = [
  {"tamper: byte change in event line",
   ["verify-chain", tampered_path], 1, run},
  {"tamper: wrong public key",
   ["verify-chain", "--pubkey", wrong_pub_path, sealed], 2, run},
  {"tamper: wrong HMAC key",
   ["verify-seal", "--hmac-key", wrong_hmac_path, sealed], 3, run}
]
|> Enum.map(fn {name, args, expected, run_fn} ->
  {out, code} = run_fn.(args)
  pass? = code == expected
  {name, expected, code, pass?, out}
end)

# --- 7. Summary ---

all = results ++ tamper_results

IO.puts("\n=== verification results ===")
Enum.each(all, fn {name, expected, code, pass?, _out} ->
  status = if pass?, do: "PASS", else: "FAIL"
  IO.puts("  [#{status}] #{name}  (expected exit #{expected}, got #{code})")
end)

passed   = Enum.count(all, fn {_, _, _, p, _} -> p end)
total    = length(all)
all_pass = passed == total

# Cleanup. We keep the sandbox on failure for debugging.
if all_pass do
  File.rm_rf!(sandbox)
  IO.puts("\n=== demo passed (#{passed}/#{total}) ===")
  System.halt(0)
else
  IO.puts("\n=== demo FAILED (#{passed}/#{total}) ===")
  IO.puts("sandbox kept for inspection: #{sandbox}")
  Enum.each(all, fn {name, _, _, pass?, out} ->
    unless pass? do
      IO.puts("\n--- #{name} ---")
      IO.puts(out)
    end
  end)
  System.halt(1)
end
