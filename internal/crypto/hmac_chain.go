// Package crypto provides HMAC chain verification for audit events.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

const ZeroHMAC = "0000000000000000000000000000000000000000000000000000000000000000"

// ComputeEventHMAC computes the expected HMAC for an audit event using the
// node's PSK and the previous event's HMAC (chain linkage).
//
// Formula: HMAC-SHA256(psk, prev_hmac_bytes || canonical_json(event))
//
// The event must NOT include the hmac field in the canonical form — that would
// be circular. Pass the event struct with HMAC cleared/empty.
func ComputeEventHMAC(psk string, prevHMAC string, eventJSON []byte) string {
	canonical := canonicalJSON(eventJSON)
	prevBytes, _ := hex.DecodeString(prevHMAC)
	if len(prevBytes) == 0 {
		prevBytes, _ = hex.DecodeString(ZeroHMAC)
	}
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(prevBytes)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyEventHMAC checks whether the event's HMAC matches the expected chain.
func VerifyEventHMAC(psk string, prevHMAC string, eventJSON []byte, claimedHMAC string) bool {
	expected := ComputeEventHMAC(psk, prevHMAC, eventJSON)
	return hmac.Equal([]byte(expected), []byte(claimedHMAC))
}

// canonicalJSON re-serializes JSON with keys sorted lexicographically (RFC 8785
// JCS-lite). This ensures the canonical form is immune to struct field reordering
// or key insertion across CLI versions.
func canonicalJSON(raw []byte) []byte {
	var obj interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw
	}
	b, err := marshalCanonical(obj)
	if err != nil {
		return raw
	}
	return b
}

func marshalCanonical(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kb, _ := json.Marshal(k)
			buf = append(buf, kb...)
			buf = append(buf, ':')
			vb, err := marshalCanonical(val[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
		}
		buf = append(buf, '}')
		return buf, nil
	case []interface{}:
		buf := []byte{'['}
		for i, item := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			ib, err := marshalCanonical(item)
			if err != nil {
				return nil, err
			}
			buf = append(buf, ib...)
		}
		buf = append(buf, ']')
		return buf, nil
	default:
		return json.Marshal(val)
	}
}
