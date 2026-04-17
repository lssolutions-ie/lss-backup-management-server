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
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/config"
	"github.com/lssolutions-ie/lss-management-server/internal/db"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
	"golang.org/x/crypto/bcrypt"
)

var webLg = logx.Component("web")

type contextKey int

const (
	ctxUser contextKey = iota
	ctxSession
)

// Server holds all shared dependencies for web handlers.
type Server struct {
	DB         *db.DB
	Config     *config.Config
	AppKey     []byte
	ConfigPath string // path to the config file (for backup)
}

// PageData is passed to every authenticated template.
type PageData struct {
	User        *models.User
	CSRFToken   string
	Flash       string
	Version     string
	SettingsTab string // active sidebar item on settings pages
}

// ServerVersion is set at startup from main.Version.
var ServerVersion = "dev"

// sshCredCache stores SSH credentials in memory per session+node.
// Credentials are never persisted — they live only as long as the session.
var sshCredCache = struct {
	sync.Mutex
	creds map[string]sshCred // key: "sessionToken:nodeID"
}{creds: make(map[string]sshCred)}

type sshCred struct {
	Username string
	Password string
}

func sshCredKey(sessionToken string, nodeID uint64) string {
	return fmt.Sprintf("%s:%d", sessionToken, nodeID)
}

// CacheSSHCreds stores SSH credentials for a session+node combination.
func CacheSSHCreds(sessionToken string, nodeID uint64, username, password string) {
	sshCredCache.Lock()
	defer sshCredCache.Unlock()
	sshCredCache.creds[sshCredKey(sessionToken, nodeID)] = sshCred{username, password}
}

// GetCachedSSHCreds returns cached SSH credentials, or empty strings if none.
func GetCachedSSHCreds(sessionToken string, nodeID uint64) (username, password string) {
	sshCredCache.Lock()
	defer sshCredCache.Unlock()
	c := sshCredCache.creds[sshCredKey(sessionToken, nodeID)]
	return c.Username, c.Password
}

// ClearSessionSSHCreds removes all SSH credentials for a session (called on logout).
func ClearSessionSSHCreds(sessionToken string) {
	sshCredCache.Lock()
	defer sshCredCache.Unlock()
	for k := range sshCredCache.creds {
		if len(k) > len(sessionToken) && k[:len(sessionToken)+1] == sessionToken+":" {
			delete(sshCredCache.creds, k)
		}
	}
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
	return PageData{User: user, CSRFToken: csrf, Flash: flash, Version: ServerVersion}
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
		"int64": func(v uint64) int64 { return int64(v) },
		"bytesFmt": func(b int64) string {
			const (
				gb = 1024 * 1024 * 1024
				mb = 1024 * 1024
				kb = 1024
			)
			sign := ""
			abs := b
			if b < 0 {
				sign = "-"
				abs = -b
			}
			switch {
			case abs >= gb:
				return fmt.Sprintf("%s%.1f GB", sign, float64(abs)/float64(gb))
			case abs >= mb:
				return fmt.Sprintf("%s%.1f MB", sign, float64(abs)/float64(mb))
			case abs >= kb:
				return fmt.Sprintf("%s%.0f KB", sign, float64(abs)/float64(kb))
			default:
				return fmt.Sprintf("%s%d B", sign, abs)
			}
		},
		"deref": func(p *uint64) uint64 {
			if p == nil {
				return 0
			}
			return *p
		},
		"jsonStr": func(s string) template.JS {
			b, err := json.Marshal(s)
			if err != nil {
				return template.JS(`""`)
			}
			return template.JS(string(b))
		},
		"rawJSON": func(s string) template.JS {
			if s == "" {
				return template.JS("null")
			}
			return template.JS(s)
		},
		"uniqueClients": func(list []*db.EnrichedAnomaly) []string {
			seen := map[string]bool{}
			var out []string
			for _, a := range list {
				if a.ClientName != "" && !seen[a.ClientName] {
					seen[a.ClientName] = true
					out = append(out, a.ClientName)
				}
			}
			sort.Strings(out)
			return out
		},
		"uniqueNodes": func(list []*db.EnrichedAnomaly) []string {
			seen := map[string]bool{}
			var out []string
			for _, a := range list {
				if a.NodeName != "" && !seen[a.NodeName] {
					seen[a.NodeName] = true
					out = append(out, a.NodeName)
				}
			}
			sort.Strings(out)
			return out
		},
		"versionLT": func(a, b string) bool {
			return versionLessThan(a, b)
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

	parseFiles := []string{"templates/base.html", "templates/" + name}
	// Include the settings sidebar partial for settings-related pages.
	if strings.HasPrefix(name, "settings") || name == "tuning.html" || name == "backup.html" ||
		name == "smtp_settings.html" || name == "dr_settings.html" || name == "update_settings.html" ||
		name == "pending_nodes.html" {
		parseFiles = append(parseFiles, "templates/settings_sidebar.html")
	}
	tmpl, err := template.New("base.html").Funcs(funcs).ParseFiles(parseFiles...)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		logx.FromContext(r.Context()).Error("template execute failed", "name", name, "err", err.Error())
	}
}

// renderStandalone renders a standalone template (login, setup) without base.html.
func (s *Server) renderStandalone(w http.ResponseWriter, status int, name string, data interface{}) {
	tmpl, err := template.ParseFiles("templates/" + name)
	if err != nil {
		webLg.Error("template parse failed", "name", name, "err", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	if err := tmpl.Execute(w, data); err != nil {
		webLg.Error("template execute failed", "name", name, "err", err.Error())
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
			logx.FromContext(r.Context()).Warn("get session failed", "err", err.Error())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		now := time.Now()

		if sess == nil || now.After(sess.ExpiresAt) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Absolute timeout: 2 hours from session creation.
		if now.Sub(sess.CreatedAt) > 2*time.Hour {
			_ = s.DB.DeleteSession(token)
			s.clearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Idle timeout: 30 minutes since last activity.
		if now.Sub(sess.LastActiveAt) > 30*time.Minute {
			_ = s.DB.DeleteSession(token)
			s.clearSessionCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Touch session to track activity.
		_ = s.DB.TouchSession(token)

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

		// Force setup: redirect to password change or 2FA setup if needed.
		// Allow access to the setup endpoints themselves to avoid redirect loops.
		path := r.URL.Path
		setupAllowed := path == "/settings/force-password" || path == "/settings/2fa/setup" || path == "/logout"
		if !setupAllowed {
			// Step 1: if force_setup and password is still the default, change it first.
			if user.ForceSetup && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte("lssbackuppassword")) == nil {
				http.Redirect(w, r, "/settings/force-password", http.StatusSeeOther)
				return
			}
			// Step 2: all users must have 2FA enabled.
			if !user.TOTPEnabled {
				http.Redirect(w, r, "/settings/2fa/setup", http.StatusSeeOther)
				return
			}
			// Clear force_setup flag once both steps are done.
			if user.ForceSetup {
				_ = s.DB.ClearForceSetup(user.ID)
			}
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

// RequireManagerOrAbove wraps RequireAuth and checks for superadmin or manager role.
func (s *Server) RequireManagerOrAbove(next http.HandlerFunc) http.HandlerFunc {
	return s.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(ctxUser).(*models.User)
		if !user.CanManageUsers() {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// EnforceBrowseRepo returns true if the current user can browse repos/snapshots.
// Returns false and writes 403 for guests.
func (s *Server) EnforceBrowseRepo(w http.ResponseWriter, r *http.Request) bool {
	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil || !user.CanBrowseRepo() {
		http.Error(w, "Forbidden — insufficient permissions", http.StatusForbidden)
		return false
	}
	return true
}

// EffectiveNodeAccess returns the effective AccessLevel a user has on a node.
// Superadmin always gets 'manage'. Others go through client-scope + tag rules + per-user overrides,
// then capped by role (user/guest → max 'view').
func (s *Server) EffectiveNodeAccess(user *models.User, nodeID uint64) models.AccessLevel {
	if user == nil {
		return models.AccessNone
	}
	if user.IsSuperAdmin() {
		return models.AccessManage
	}
	visible, err := s.DB.ListVisibleNodeIDsForUser(user.ID)
	if err != nil {
		return models.AccessNone
	}
	acc, ok := visible[nodeID]
	if !ok {
		return models.AccessNone
	}
	return models.CapByRole(user.Role, acc)
}

// EnforceNodeManage returns true if the user has 'manage' on the node; else writes 403.
func (s *Server) EnforceNodeManage(w http.ResponseWriter, r *http.Request, nodeID uint64) bool {
	user, _ := r.Context().Value(ctxUser).(*models.User)
	access := s.EffectiveNodeAccess(user, nodeID)
	if !access.CanManage() {
		http.Error(w, "Forbidden — insufficient permissions for this node", http.StatusForbidden)
		return false
	}
	return true
}

// EnforceNodeView returns true if the user has at least 'view' on the node; else writes 404 (don't leak).
func (s *Server) EnforceNodeView(w http.ResponseWriter, r *http.Request, nodeID uint64) bool {
	user, _ := r.Context().Value(ctxUser).(*models.User)
	access := s.EffectiveNodeAccess(user, nodeID)
	if !access.AtLeastView() {
		http.NotFound(w, r)
		return false
	}
	return true
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

// setSessionCookie sets an ephemeral session cookie (no MaxAge = dies on browser close).
func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.Config.Session.CookieName,
		Value:    token,
		Path:     "/",
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
		webLg.Error("set psk flash failed", "err", err.Error())
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

// loginRateLimiter tracks failed login attempts per IP.
var loginRateLimiter = struct {
	sync.Mutex
	attempts map[string][]time.Time
}{attempts: make(map[string][]time.Time)}

const (
	loginMaxAttempts = 5               // max failures per window
	loginWindow      = 5 * time.Minute // sliding window
	loginLockout     = 15 * time.Minute // lockout after max failures
)

// checkLoginAttempts returns true if the IP is allowed to attempt login.
func checkLoginAttempts(ip, _ string) bool {
	// Strip port from RemoteAddr.
	if h, _, ok := strings.Cut(ip, ":"); ok {
		ip = h
	}

	loginRateLimiter.Lock()
	defer loginRateLimiter.Unlock()

	now := time.Now()
	cutoff := now.Add(-loginLockout)

	// Prune old entries.
	attempts := loginRateLimiter.attempts[ip]
	valid := attempts[:0]
	for _, t := range attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	loginRateLimiter.attempts[ip] = valid

	return len(valid) < loginMaxAttempts
}

// recordLoginFailure records a failed login attempt for rate limiting.
func recordLoginFailure(ip string) {
	if h, _, ok := strings.Cut(ip, ":"); ok {
		ip = h
	}

	loginRateLimiter.Lock()
	defer loginRateLimiter.Unlock()
	loginRateLimiter.attempts[ip] = append(loginRateLimiter.attempts[ip], time.Now())
}

// versionLessThan compares two semver strings (with optional "v" prefix).
// Returns true if a < b. Non-numeric parts are treated as 0.
func versionLessThan(a, b string) bool {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	for i := 0; i < len(ap) || i < len(bp); i++ {
		var ai, bi int
		if i < len(ap) {
			fmt.Sscanf(ap[i], "%d", &ai)
		}
		if i < len(bp) {
			fmt.Sscanf(bp[i], "%d", &bi)
		}
		if ai < bi {
			return true
		}
		if ai > bi {
			return false
		}
	}
	return false
}
