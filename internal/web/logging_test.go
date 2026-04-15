package web

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// statusCapturingWriter MUST implement http.Hijacker — without it,
// gorilla/websocket's Upgrade fails with "response does not implement
// http.Hijacker" and every /ws/ tunnel breaks.
//
// This test was added after a real production-down incident in v1.11.6 where
// the access-log middleware wrapper silently dropped the Hijack capability.
func TestStatusCapturingWriter_ImplementsHijacker(t *testing.T) {
	var w http.ResponseWriter = &statusCapturingWriter{ResponseWriter: hijackableRW{}}
	if _, ok := w.(http.Hijacker); !ok {
		t.Fatal("statusCapturingWriter must implement http.Hijacker")
	}
}

func TestStatusCapturingWriter_ImplementsFlusher(t *testing.T) {
	var w http.ResponseWriter = &statusCapturingWriter{ResponseWriter: hijackableRW{}}
	if _, ok := w.(http.Flusher); !ok {
		t.Fatal("statusCapturingWriter must implement http.Flusher")
	}
}

// statusCapturingWriter.Hijack should error politely when the underlying
// writer doesn't support Hijack (e.g. a test responder), not panic.
func TestStatusCapturingWriter_HijackOnNonHijackable(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &statusCapturingWriter{ResponseWriter: rec}
	if _, _, err := w.Hijack(); err == nil {
		t.Fatal("Hijack() on non-hijackable underlying writer should return an error, not panic")
	}
}

// hijackableRW is a stub that satisfies http.ResponseWriter + http.Hijacker +
// http.Flusher so the type-assertion tests pass without touching a real socket.
type hijackableRW struct{}

func (hijackableRW) Header() http.Header        { return http.Header{} }
func (hijackableRW) Write(p []byte) (int, error) { return len(p), nil }
func (hijackableRW) WriteHeader(int)             {}
func (hijackableRW) Flush()                      {}
func (hijackableRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, http.ErrNotSupported
}
