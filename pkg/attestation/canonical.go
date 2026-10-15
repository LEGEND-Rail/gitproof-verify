package attestation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonicalize takes an arbitrary Go value, marshals it, and normalizes it
// according to RFC 8785 JSON Canonicalization Scheme (JCS).
// Recursively sorts object keys and removes formatting whitespace. // CITED — IETF RFC 8785
func Canonicalize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: marshal failed: %w", err)
	}

	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("canonicalize: unmarshal failed: %w", err)
	}

	var buf bytes.Buffer
	if err := encodeCanonical(&buf, decoded); err != nil {
		return nil, fmt.Errorf("canonicalize: canonical encoding failed: %w", err)
	}

	return buf.Bytes(), nil
}

func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	case float64:
		// Format numbers deterministically
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		buf.WriteByte('{')
		// Sort keys lexicographically (UTF-16 code unit / byte order)
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(keyBytes)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical type: %T", v)
	}
	return nil
}
