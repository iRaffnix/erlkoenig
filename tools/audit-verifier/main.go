// audit-verifier — offline verifier for SPEC-AS-005 audit logs.
//
// A statically-linked Go binary the customer hands to their
// auditor. Reads erlkoenig audit JSONL files plus optional Ed25519
// public key and HMAC key, returns 0 on full validation, non-zero
// otherwise. No network, no external dependencies.
//
// Subcommands:
//   verify-chain [--pubkey PATH] [--start-prev HEX] FILE
//       Walk a (live or sealed) audit log, recompute the SHA-256
//       hash chain, optionally verify each event's Ed25519 signature.
//
//   verify-seal --hmac-key PATH FILE
//       Verify a sealed file's HMAC over the day's bytes.
//
//   verify-day [--pubkey PATH] --hmac-key PATH SEALED-FILE
//       Combined: chain + signatures + seal HMAC.
//
// Exit codes:
//   0  — verification succeeded
//   1  — chain broken (prev_hash or this_hash mismatch)
//   2  — Ed25519 signature invalid
//   3  — HMAC mismatch on sealed file
//   4  — file not found / read error / argument error

package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	exitOK              = 0
	exitChainBroken     = 1
	exitSigInvalid      = 2
	exitHmacMismatch    = 3
	exitArgOrIOError    = 4
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitArgOrIOError)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "verify-chain":
		os.Exit(cmdVerifyChain(args))
	case "verify-seal":
		os.Exit(cmdVerifySeal(args))
	case "verify-day":
		os.Exit(cmdVerifyDay(args))
	case "version", "--version", "-v":
		fmt.Println(version)
		os.Exit(exitOK)
	case "help", "-h", "--help":
		usage()
		os.Exit(exitOK)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", cmd)
		usage()
		os.Exit(exitArgOrIOError)
	}
}

func usage() {
	fmt.Fprint(os.Stderr,
		`audit-verifier — offline verifier for SPEC-AS-005 audit logs

usage:
  audit-verifier verify-chain [--pubkey PATH] [--start-prev HEX] FILE
  audit-verifier verify-seal --hmac-key PATH FILE
  audit-verifier verify-day [--pubkey PATH] --hmac-key PATH SEALED-FILE
  audit-verifier version
  audit-verifier help

exit codes:
  0  ok
  1  chain broken (hash mismatch)
  2  ed25519 signature invalid
  3  hmac mismatch on sealed file
  4  argument or i/o error
`)
}

func cmdVerifyChain(args []string) int {
	fs := flag.NewFlagSet("verify-chain", flag.ContinueOnError)
	pubkeyPath := fs.String("pubkey", "", "Ed25519 public key file (raw 32 bytes)")
	startPrev := fs.String("start-prev", "", "expected prev_hash of first event (default: 64 zeros)")
	if err := fs.Parse(args); err != nil {
		return exitArgOrIOError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "verify-chain: expected one FILE argument")
		return exitArgOrIOError
	}
	file := fs.Arg(0)

	var pubKey ed25519.PublicKey
	if *pubkeyPath != "" {
		raw, err := readKey(*pubkeyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read pubkey:", err)
			return exitArgOrIOError
		}
		pubKey = ed25519.PublicKey(raw)
	}

	res, err := VerifyChain(file, pubKey, *startPrev)
	if err != nil {
		return classifyAndPrint(err)
	}
	fmt.Printf("ok: %d event(s), chain head %s\n", res.EventCount, res.ChainHead)
	if res.HasSeal {
		fmt.Printf("    last event is audit.seal — anchor for next day: %s\n", res.SealAnchor)
	}
	return exitOK
}

func cmdVerifySeal(args []string) int {
	fs := flag.NewFlagSet("verify-seal", flag.ContinueOnError)
	hmacPath := fs.String("hmac-key", "", "HMAC key file (raw 32 bytes) — required")
	if err := fs.Parse(args); err != nil {
		return exitArgOrIOError
	}
	if *hmacPath == "" {
		fmt.Fprintln(os.Stderr, "verify-seal: --hmac-key is required")
		return exitArgOrIOError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "verify-seal: expected one FILE argument")
		return exitArgOrIOError
	}
	file := fs.Arg(0)

	hmacKey, err := readKey(*hmacPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read hmac key:", err)
		return exitArgOrIOError
	}

	res, err := VerifySeal(file, hmacKey)
	if err != nil {
		return classifyAndPrint(err)
	}
	fmt.Printf("ok: seal verified — %d event(s), %d bytes, anchor %s\n",
		res.EventCount, res.ByteCount, res.SealAnchor)
	return exitOK
}

// cmdVerifyDay = verify-chain with pubkey + verify-seal in one call.
// Use this on a sealed daily file to get full validation in one
// invocation, the most common operator/auditor pattern.
func cmdVerifyDay(args []string) int {
	fs := flag.NewFlagSet("verify-day", flag.ContinueOnError)
	pubkeyPath := fs.String("pubkey", "", "Ed25519 public key file (raw 32 bytes)")
	hmacPath := fs.String("hmac-key", "", "HMAC key file (raw 32 bytes) — required")
	if err := fs.Parse(args); err != nil {
		return exitArgOrIOError
	}
	if *hmacPath == "" {
		fmt.Fprintln(os.Stderr, "verify-day: --hmac-key is required")
		return exitArgOrIOError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "verify-day: expected one SEALED-FILE argument")
		return exitArgOrIOError
	}
	file := fs.Arg(0)

	hmacKey, err := readKey(*hmacPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read hmac key:", err)
		return exitArgOrIOError
	}

	var pubKey ed25519.PublicKey
	if *pubkeyPath != "" {
		raw, err := readKey(*pubkeyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read pubkey:", err)
			return exitArgOrIOError
		}
		pubKey = ed25519.PublicKey(raw)
	}

	if _, err := VerifyChain(file, pubKey, ""); err != nil {
		return classifyAndPrint(err)
	}
	res, err := VerifySeal(file, hmacKey)
	if err != nil {
		return classifyAndPrint(err)
	}
	fmt.Printf("ok: chain + seal verified — %d events, %d bytes, anchor %s\n",
		res.EventCount, res.ByteCount, res.SealAnchor)
	return exitOK
}

// classifyAndPrint maps an error to the right exit code based on
// substring matching. Cheap and correct given our error messages
// originate from this codebase.
func classifyAndPrint(err error) int {
	msg := err.Error()
	fmt.Fprintln(os.Stderr, "FAIL:", msg)
	switch {
	case strings.Contains(msg, "ed25519"), strings.Contains(msg, "signature"):
		return exitSigInvalid
	case strings.Contains(msg, "hmac"), strings.Contains(msg, "seal"):
		return exitHmacMismatch
	case strings.Contains(msg, "chain"), strings.Contains(msg, "this_hash"),
		strings.Contains(msg, "prev_hash"):
		return exitChainBroken
	default:
		return exitArgOrIOError
	}
}
