package crypto

import (
	"encoding/json"
	"testing"
)

func TestCanonicalJSON_SortsKeys(t *testing.T) {
	input := `{"z":1,"a":2,"m":3}`
	got := string(canonicalJSON([]byte(input)))
	want := `{"a":2,"m":3,"z":1}`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestCanonicalJSON_Nested(t *testing.T) {
	input := `{"b":{"z":1,"a":2},"a":3}`
	got := string(canonicalJSON([]byte(input)))
	want := `{"a":3,"b":{"a":2,"z":1}}`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestComputeEventHMAC_ChainLinkage(t *testing.T) {
	psk := "test-psk-secret"

	event1 := map[string]interface{}{
		"seq": 1, "ts": 1776000000, "category": "daemon_started",
		"severity": "info", "actor": "system", "message": "Daemon started",
	}
	e1bytes, _ := json.Marshal(event1)

	h1 := ComputeEventHMAC(psk, ZeroHMAC, e1bytes)
	if h1 == "" || h1 == ZeroHMAC {
		t.Fatal("first HMAC should be non-zero")
	}

	event2 := map[string]interface{}{
		"seq": 2, "ts": 1776000001, "category": "tunnel_connected",
		"severity": "info", "actor": "system", "message": "Connected",
	}
	e2bytes, _ := json.Marshal(event2)

	h2 := ComputeEventHMAC(psk, h1, e2bytes)
	if h2 == "" || h2 == h1 {
		t.Fatal("second HMAC should differ from first")
	}

	// Verify the chain: h2 depends on h1.
	if !VerifyEventHMAC(psk, h1, e2bytes, h2) {
		t.Fatal("chain verification failed for event 2")
	}
	// Tamper: wrong prev_hmac.
	if VerifyEventHMAC(psk, ZeroHMAC, e2bytes, h2) {
		t.Fatal("tampered prev_hmac should fail verification")
	}
	// Tamper: modified event body.
	event2["message"] = "Tampered"
	e2tampered, _ := json.Marshal(event2)
	if VerifyEventHMAC(psk, h1, e2tampered, h2) {
		t.Fatal("tampered event body should fail verification")
	}
}

func TestComputeEventHMAC_EmptyVsZeroPrevDiffer(t *testing.T) {
	psk := "my-psk"
	event := map[string]interface{}{"seq": 1, "ts": 1, "category": "test"}
	eb, _ := json.Marshal(event)

	hEmpty := ComputeEventHMAC(psk, "", eb)
	hZero := ComputeEventHMAC(psk, ZeroHMAC, eb)
	// Now that we use raw string bytes (not hex-decoded), ZeroHMAC is 64 ASCII
	// '0' characters = different from "" (0 bytes). They MUST differ.
	if hEmpty == hZero {
		t.Fatal("empty prev and ZeroHMAC should produce different results")
	}
}

func TestComputeEventHMAC_CLITestVector(t *testing.T) {
	// Test vector from CLI session — validates both sides agree on the HMAC
	// computation using raw hex string bytes for prev (not hex-decoded).
	key := "test-key-abc"
	prev := "deadbeef"
	canonical := []byte(`{"seq":1,"ts":1000}`)
	got := ComputeEventHMAC(key, prev, canonical)
	want := "21e52fc9418c371eb07e047e323509d5944426cc379a83444afeb8b4212307fd"
	if got != want {
		t.Fatalf("CLI test vector mismatch: got %s, want %s", got, want)
	}
}
