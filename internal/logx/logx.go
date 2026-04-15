// Package logx centralises structured (slog) logging for the server.
//
// Contract:
//   - All new code uses slog, not the legacy log.Printf.
//   - Handlers get a per-request logger from FromContext(ctx) that carries the
//     request ID; use it so every line for one request is stitchable.
//   - Call Component(name) to get a logger tagged with a component field; this
//     is the right entry point in packages that don't have a request context.
//   - Use Redact() for anything secret (PSKs, passwords, session cookies).
package logx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
)

type ctxKey int

const (
	ctxLogger ctxKey = iota
	ctxReqID
)

// Init configures the global slog default logger as JSON to stderr.
// Level comes from LSS_LOG_LEVEL (debug|info|warn|error), default info.
// The legacy `log` package is also redirected so existing log.Printf calls
// keep flowing out the same stream (as plain messages, not structured).
func Init() {
	var level slog.Level
	switch strings.ToLower(os.Getenv("LSS_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	logger := slog.New(h).With("service", "lss-mgmt")
	slog.SetDefault(logger)

	// Route legacy log.Printf through slog at INFO so mixed callers still
	// produce JSON lines. The "msg" field is the raw text.
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(slog.NewLogLogger(h, slog.LevelInfo).Writer())
}

// Component returns a logger tagged with the given component name.
func Component(name string) *slog.Logger {
	return slog.Default().With("component", name)
}

// NewReqID returns a short random hex ID suitable for request correlation.
func NewReqID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "000000000000"
	}
	return hex.EncodeToString(b[:])
}

// WithRequest returns a context carrying a per-request logger and request ID.
func WithRequest(ctx context.Context, reqID string, base *slog.Logger) context.Context {
	lg := base.With("req_id", reqID)
	ctx = context.WithValue(ctx, ctxLogger, lg)
	ctx = context.WithValue(ctx, ctxReqID, reqID)
	return ctx
}

// FromContext returns the per-request logger if present; otherwise the default.
func FromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return slog.Default()
	}
	if lg, ok := ctx.Value(ctxLogger).(*slog.Logger); ok && lg != nil {
		return lg
	}
	return slog.Default()
}

// ReqID returns the request ID attached to this context, or "" if none.
func ReqID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(ctxReqID).(string); ok {
		return id
	}
	return ""
}

// Redact returns a fixed placeholder when v is non-empty, else empty string.
// Use for PSKs, passwords, raw tokens — never emit the real value.
func Redact(v string) string {
	if v == "" {
		return ""
	}
	return fmt.Sprintf("***(%d)", len(v))
}
