package web

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/config"
	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type contextKey int

const (
	ctxUser contextKey = iota
	ctxSession
)

// Server holds all shared dependencies for web handlers.
type Server struct {
	DB     *db.DB
	Config *config.Config
	AppKey []byte
}

// PageData is passed to every authenticated template.
type PageData struct {
	User      *models.User
	CSRFToken string
	Flash     string
}

// newPageData builds PageData from the request context.
func (s *Server) newPageData(r *http.Request) PageData {
	user, _ := r.Context().Value(ctxUser).(*models.User)
	tok, _ := r.Context().Value(ctxSession).(string)
	csrf := s.csrfToken(tok)
	flash := ""
	if c, err := r.Cookie("flash"); err == nil {
		flash = c.Value
	}
	return PageData{User: user, CSRFToken: csrf, Flash: flash}
}

// render executes the named template using base.html as the layout.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, data interface{}) {
	// clear flash cookie before rendering
	if _, err := r.Cookie("flash"); err == nil {
		http.SetCookie(w, &http.Cookie{Name: "flash", MaxAge: -1, Path: "/"})
	}

	funcs := template.FuncMap{
		"formatTime": func(t *time.Time) string {
			if t == nil {
				return "—"
			}
			return t.Format("2006-01-02 15:04:05")
		},
		"formatDuration": func(secs int) string {
			if secs < 60 {
				return fmt.Sprintf("%ds", secs)
			}
			return fmt.Sprintf("%dm %ds", secs/60, secs%60)
		},
		"bytesFmt": func(b int64) string {
			const (
				gb = 1024 * 1024 * 1024
				mb = 1024 * 1024
			)
			switch {
			case b >= gb:
				return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
			case b >= mb:
				return fmt.Sprintf("%.0f MB", float64(b)/float64(mb))
			default:
				return fmt.Sprintf("%d B", b)
			}
		},
		"prettyJSON": func(s string) string {
			if s == "" {
				return ""
			}
			var v interface{}
			if err := json.Unmarshal([]byte(s), &v); err != nil {
				return s
			}
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return s
			}
			return string(b)
		},
	}

	tmpl, err := template.New("base.html").Funcs(funcs).ParseFiles("templates/base.html", "templates/"+name)
	if err != nil {
		log.Printf("template parse %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		log.Printf("template execute %s: %v", name, err)
	}
}

// renderStandalone renders a standalone template (login, setup) without base.html.
func (s *Server) renderStandalone(w http.ResponseWriter, status int, name string, data interface{}) {
	tmpl, err := template.ParseFiles("templates/" + name)
	if err != nil {
		log.Printf("template parse %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("template execute %s: %v", name, err)
	}
}

// RequireAuth is middleware that checks for a valid session cookie.
func (s *Server) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(s.Config.Session.CookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		token := cookie.Value

		sess, err := s.DB.GetSessionByToken(token)
		if err != nil {
			log.Printf("auth: get session: %v", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if sess == nil || time.Now().After(sess.ExpiresAt) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Timing-safe token comparison
		tokenBytes := []byte(token)
		sessBytes := []byte(sess.Token)
		if subtle.ConstantTimeCompare(tokenBytes, sessBytes) != 1 {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		user, err := s.DB.GetUserByID(sess.UserID)
		if err != nil || user == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), ctxUser, user)
		ctx = context.WithValue(ctx, ctxSession, token)
		next(w, r.WithContext(ctx))
	}
}

// EnforceWrite returns true if the current user may perform write actions.
// Call at the top of write handlers; returns false and writes 403 for viewers.
func (s *Server) EnforceWrite(w http.ResponseWriter, r *http.Request) bool {
	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil || !user.CanWrite() {
		http.Error(w, "Forbidden — read-only user", http.StatusForbidden)
		return false
	}
	return true
}

// RequireSuperAdmin wraps RequireAuth and additionally checks role.
func (s *Server) RequireSuperAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(ctxUser).(*models.User)
		if !user.IsSuperAdmin() {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// validateCSRF returns true if the CSRF token in the form matches the expected value.
func (s *Server) validateCSRF(r *http.Request) bool {
	tok, _ := r.Context().Value(ctxSession).(string)
	expected := s.csrfToken(tok)
	got := r.FormValue("csrf_token")
	return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}

// csrfToken derives a CSRF token from the session token using HMAC-SHA256.
func (s *Server) csrfToken(sessionToken string) string {
	mac := hmac.New(sha256.New, s.AppKey)
	mac.Write([]byte("csrf:" + sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// generateSessionToken returns a hex-encoded 32-byte random token.
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// setFlash sets a short-lived flash cookie.
func setFlash(w http.ResponseWriter, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "flash",
		Value:    msg,
		Path:     "/",
		MaxAge:   30,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// setSessionCookie sets the session cookie.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.Config.Session.CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   s.Config.Session.MaxAgeHours * 3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookie expires the session cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.Config.Session.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// setPSKFlash stores an AES-encrypted PSK in a short-lived cookie for one-time display.
func (s *Server) setPSKFlash(w http.ResponseWriter, psk string) {
	encrypted, err := sealValue([]byte(psk), s.AppKey)
	if err != nil {
		log.Printf("set psk flash: %v", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "psk_show",
		Value:    encrypted,
		Path:     "/",
		MaxAge:   120,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// getPSKFlash reads and clears the PSK flash cookie. Returns "" if not present.
func (s *Server) getPSKFlash(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie("psk_show")
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "psk_show",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	plain, err := openValue(cookie.Value, s.AppKey)
	if err != nil {
		return ""
	}
	return string(plain)
}

// sealValue encrypts plaintext using AES-256-GCM; key derived via SHA-256.
// Output: base64(nonce+ciphertext+tag).
func sealValue(plain, keyMaterial []byte) (string, error) {
	key := sha256sum(keyMaterial)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// openValue decrypts a sealValue output.
func openValue(encoded string, keyMaterial []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	key := sha256sum(keyMaterial)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, err
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// checkLoginAttempts is a stub for future rate-limiting. Always returns true.
func checkLoginAttempts(ip, username string) bool {
	return true
}
