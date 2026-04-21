// Package main — canonical JSON encoder.
//
// Must produce byte-for-byte identical output to the Erlang
// canonical_json/1 in apps/erlkoenig/src/erlkoenig_audit.erl.
// Two implementations differ here ⇒ verification breaks silently.
//
// Encoding rules (mirror erlkoenig_audit:canonical_json/1):
//   - maps          : keys sorted lexicographically (UTF-8 byte order),
//                     no whitespace, "k":v form
//   - lists         : comma-separated, no whitespace
//   - strings       : escape \\, \", \n; otherwise verbatim UTF-8
//   - booleans      : true / false
//   - null          : null
//   - integers      : decimal, no leading sign for non-negative
//   - floats        : up to 6 decimals, trailing zeros stripped
//                     but always at least one decimal (matches
//                     Erlang's float_to_binary(F,
//                     [{decimals, 6}, compact])).
//
// Numbers must be decoded via json.Decoder with UseNumber() so we
// can tell integers from floats — Go's default decoder casts
// everything to float64 which loses the distinction.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CanonicalJSON encodes v using the canonical rules above.
// v should come from a json.Decoder with UseNumber().
func CanonicalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, x)
	case json.Number:
		return writeNumber(buf, x)
	case map[string]interface{}:
		writeMap(buf, x)
	case []interface{}:
		return writeList(buf, x)
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

func writeMap(buf *bytes.Buffer, m map[string]interface{}) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeString(buf, k)
		buf.WriteByte(':')
		_ = writeCanonical(buf, m[k])
	}
	buf.WriteByte('}')
}

func writeList(buf *bytes.Buffer, l []interface{}) error {
	buf.WriteByte('[')
	for i, e := range l {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonical(buf, e); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

// writeString writes a JSON-escaped, double-quoted string.
// Erlang's escape_str/1 only escapes \, ", and \n explicitly.
// Everything else (including control characters and non-ASCII)
// passes through as the original UTF-8 bytes. We mirror exactly.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			buf.WriteString(`\\`)
		case '"':
			buf.WriteString(`\"`)
		case '\n':
			buf.WriteString(`\n`)
		default:
			buf.WriteByte(c)
		}
	}
	buf.WriteByte('"')
}

// writeNumber preserves integer form when the JSON token has no
// decimal point or exponent. For genuine floats we reformat to
// match Erlang's `float_to_binary(F, [{decimals, 6}, compact])`:
// at most 6 fractional digits, trailing zeros stripped, but at
// least one digit after the decimal point.
func writeNumber(buf *bytes.Buffer, n json.Number) error {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		// Integer — token is already canonical (no leading zeros
		// allowed in JSON, optional minus sign).
		buf.WriteString(s)
		return nil
	}
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("canonical: invalid number %q: %w", s, err)
	}
	buf.WriteString(formatFloatLikeErlang(f))
	return nil
}

// formatFloatLikeErlang mirrors Erlang's
// `float_to_binary(F, [{decimals, 6}, compact])`. Examples:
//
//	1.5            -> "1.5"
//	1.50           -> "1.5"
//	100            -> "100.0"   (Erlang always keeps the decimal)
//	1.123456789    -> "1.123457"
func formatFloatLikeErlang(f float64) string {
	s := strconv.FormatFloat(f, 'f', 6, 64)
	// strconv gives "100.000000". Strip trailing zeros, then strip
	// the trailing dot if all decimals were zero, then re-add ".0".
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		s = strings.TrimRight(s, "0")
		if strings.HasSuffix(s, ".") {
			s += "0"
		}
	}
	return s
}
