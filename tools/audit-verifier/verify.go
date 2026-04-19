// verify.go — chain, signature, and seal verification.
//
// Mirrors:
//   - erlkoenig_audit:verify_chain/1,2 (hash chain + optional Ed25519)
//   - erlkoenig_audit:verify_seal/2     (HMAC-SHA-256 over a sealed file)
//
// All cryptographic primitives are stdlib; no external dependencies.
// CGO_ENABLED=0 produces a fully static binary suitable for shipping
// to a customer auditor.

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// genesisHash is the prev_hash of the first event in any chain
// (64 hex zeros). Must match GENESIS_HASH in erlkoenig_audit.erl.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// VerifyResult summarises a successful verification of one file.
type VerifyResult struct {
	EventCount int    // events validated
	ChainHead  string // hex this_hash of the last event
	HasSeal    bool   // last event is type=audit.seal
	SealAnchor string // when HasSeal: the seal event's this_hash (next-day prev_hash)
	ByteCount  int64  // when HasSeal: byte_count claimed by the seal event
}

// VerifyChain walks an audit log file, recomputing every event's
// this_hash and verifying the prev_hash chain. If pubKey is non-nil
// (raw 32 bytes), each event's signature is also verified against
// it. Genesis prevHash defaults to genesisHash; pass a non-empty
// override to continue across a sealed-file boundary.
func VerifyChain(path string, pubKey ed25519.PublicKey, startPrev string) (*VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	prev := startPrev
	if prev == "" {
		prev = genesisHash
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // up to 16 MB lines
	lineNo := 0
	res := &VerifyResult{}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		lineNo++

		event, err := decodeEvent(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: decode: %w", lineNo, err)
		}

		actualPrev, _ := event["prev_hash"].(string)
		storedHash, _ := event["this_hash"].(string)

		if actualPrev != prev {
			return nil, fmt.Errorf("line %d: chain break — prev_hash %q does not match expected %q",
				lineNo, actualPrev, prev)
		}

		recomputed, err := computeThisHash(event)
		if err != nil {
			return nil, fmt.Errorf("line %d: hash recompute: %w", lineNo, err)
		}
		if recomputed != storedHash {
			return nil, fmt.Errorf("line %d: chain break — this_hash mismatch (stored %q recomputed %q)",
				lineNo, storedHash, recomputed)
		}

		if pubKey != nil {
			if err := verifySignature(event, storedHash, pubKey); err != nil {
				return nil, fmt.Errorf("line %d: signature: %w", lineNo, err)
			}
		}

		prev = storedHash

		// Track if the LAST event is a seal — caller may want the
		// anchor for chaining into the next day's file.
		typ, _ := event["type"].(string)
		if typ == "audit.seal" {
			res.HasSeal = true
			res.SealAnchor = storedHash
			if bc, ok := event["byte_count"].(json.Number); ok {
				if i, err := bc.Int64(); err == nil {
					res.ByteCount = i
				}
			}
		} else {
			res.HasSeal = false
			res.SealAnchor = ""
			res.ByteCount = 0
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	res.EventCount = lineNo
	res.ChainHead = prev
	return res, nil
}

// VerifySeal verifies a sealed file's HMAC. The last line MUST be
// an audit.seal event whose details carry hmac/event_count/byte_count.
// The HMAC is computed over the first byte_count bytes of the file
// (everything BEFORE the seal event line) using the symmetric
// 32-byte hmacKey that produced the seal.
func VerifySeal(path string, hmacKey []byte) (*VerifyResult, error) {
	if len(hmacKey) != 32 {
		return nil, fmt.Errorf("hmac key must be 32 bytes, got %d", len(hmacKey))
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Find the LAST non-empty line — the seal event.
	lastLine, err := lastNonEmptyLine(raw)
	if err != nil {
		return nil, err
	}

	seal, err := decodeEvent(lastLine)
	if err != nil {
		return nil, fmt.Errorf("decode seal event: %w", err)
	}

	if t, _ := seal["type"].(string); t != "audit.seal" {
		return nil, fmt.Errorf("last line is not an audit.seal event (type=%q)", t)
	}

	expectedHex, _ := seal["hmac"].(string)
	if expectedHex == "" {
		return nil, fmt.Errorf("seal event missing hmac field")
	}

	bcNum, ok := seal["byte_count"].(json.Number)
	if !ok {
		return nil, fmt.Errorf("seal event missing byte_count field")
	}
	byteCount, err := bcNum.Int64()
	if err != nil {
		return nil, fmt.Errorf("seal event byte_count not integer: %w", err)
	}
	if byteCount > int64(len(raw)) {
		return nil, fmt.Errorf("seal byte_count %d exceeds file size %d",
			byteCount, len(raw))
	}

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(raw[:byteCount])
	actualHex := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(actualHex), []byte(expectedHex)) {
		return nil, fmt.Errorf("seal hmac mismatch (expected %q got %q)",
			expectedHex, actualHex)
	}

	storedHash, _ := seal["this_hash"].(string)
	ec, _ := seal["event_count"].(json.Number)
	ecInt, _ := ec.Int64()

	return &VerifyResult{
		EventCount: int(ecInt),
		ChainHead:  storedHash,
		HasSeal:    true,
		SealAnchor: storedHash,
		ByteCount:  byteCount,
	}, nil
}

// computeThisHash mirrors erlkoenig_audit:compute_this_hash/1.
// Removes this_hash AND signature from the event, encodes
// canonically, sha256, hex.
func computeThisHash(event map[string]interface{}) (string, error) {
	stripped := make(map[string]interface{}, len(event))
	for k, v := range event {
		if k == "this_hash" || k == "signature" {
			continue
		}
		stripped[k] = v
	}
	canon, err := CanonicalJSON(stripped)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canon)
	return hex.EncodeToString(digest[:]), nil
}

// verifySignature checks an event's Ed25519 signature against the
// raw 32 bytes of its this_hash. Pass-through when signature is
// null (event was written without a signing key).
func verifySignature(event map[string]interface{}, hexHash string, pubKey ed25519.PublicKey) error {
	sig, present := event["signature"]
	if !present || sig == nil {
		// Unsigned event — caller asked to verify but the chain
		// pre-dates signing (or was written without a key). Mirror
		// Erlang's verify_signature/3 which treats null as ok.
		return nil
	}
	hexSig, ok := sig.(string)
	if !ok {
		return fmt.Errorf("signature field is not a string (got %T)", sig)
	}
	rawHash, err := hex.DecodeString(hexHash)
	if err != nil {
		return fmt.Errorf("decode this_hash: %w", err)
	}
	rawSig, err := hex.DecodeString(hexSig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pubKey, rawHash, rawSig) {
		return fmt.Errorf("ed25519 verify failed")
	}
	return nil
}

// decodeEvent parses one JSONL line into a map with json.Number
// for all numbers (so the canonical encoder can preserve int/float
// distinction).
func decodeEvent(line []byte) (map[string]interface{}, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// lastNonEmptyLine returns the last non-empty line in raw (without
// the trailing newline).
func lastNonEmptyLine(raw []byte) ([]byte, error) {
	end := len(raw)
	for end > 0 && (raw[end-1] == '\n' || raw[end-1] == '\r') {
		end--
	}
	if end == 0 {
		return nil, fmt.Errorf("file is empty")
	}
	start := bytes.LastIndexByte(raw[:end], '\n')
	if start < 0 {
		return raw[:end], nil
	}
	return raw[start+1 : end], nil
}

// readKey reads a 32-byte raw key from path (Ed25519 public key
// or HMAC key — both are 32 bytes). Reads exactly the first 32
// bytes; longer files are truncated (matches Erlang's
// load_signing_key behaviour).
func readKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 32)
	n, err := io.ReadFull(f, buf)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (got %d bytes)", path, err, n)
	}
	return buf, nil
}
