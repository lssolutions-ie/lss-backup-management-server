package web

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

// statusCapturingWriter wraps ResponseWriter so we can log the final status.
type statusCapturingWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusCapturingWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCapturingWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// RequestLog attaches a request ID + per-request logger to every request and
// emits one access-log line for mutating HTTP methods (POST/PUT/DELETE/PATCH).
// GETs are skipped to keep the log readable.
func (s *Server) RequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = logx.NewReqID()
		}
		w.Header().Set("X-Request-ID", reqID)
		ctx := logx.WithRequest(r.Context(), reqID, logx.Component("http"))
		r = r.WithContext(ctx)

		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
		// Skip heartbeat ingest — it's high-volume and already has its own detailed log.
		skipAccess := strings.HasPrefix(r.URL.Path, "/api/v1/status") || strings.HasPrefix(r.URL.Path, "/ws/")

		start := time.Now()
		scw := &statusCapturingWriter{ResponseWriter: w}

		next.ServeHTTP(scw, r)

		if mutating && !skipAccess {
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", scw.status),
				slog.Duration("dur", time.Since(start)),
				slog.String("remote", clientIP(r)),
			}
			if u, ok := r.Context().Value(ctxUser).(*models.User); ok && u != nil {
				attrs = append(attrs, slog.String("user", u.Username))
			}
			level := slog.LevelInfo
			if scw.status >= 500 {
				level = slog.LevelError
			} else if scw.status >= 400 {
				level = slog.LevelWarn
			}
			logx.FromContext(ctx).LogAttrs(ctx, level, "access", attrs...)
		}
	})
}

func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		// First IP in the chain.
		if i := strings.IndexByte(f, ','); i > 0 {
			return strings.TrimSpace(f[:i])
		}
		return strings.TrimSpace(f)
	}
	return r.RemoteAddr
}

// Fail logs the server-side reason at the given slog level and writes
// http.Error(w, clientMsg, status). Use this instead of bare http.Error for
// any error path where the user wouldn't otherwise get a log line.
func (s *Server) Fail(w http.ResponseWriter, r *http.Request, status int, err error, clientMsg string) {
	lg := logx.FromContext(r.Context())
	attrs := []any{slog.Int("status", status), slog.String("path", r.URL.Path)}
	if err != nil {
		attrs = append(attrs, slog.String("err", err.Error()))
	}
	level := slog.LevelError
	if status < 500 {
		level = slog.LevelWarn
	}
	lg.Log(r.Context(), level, clientMsg, attrs...)
	http.Error(w, clientMsg, status)
}
