package web

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type loginPageData struct {
	PageData
	Error string
}

type setupPageData struct {
	Error string
}

type totpVerifyPageData struct {
	Error string
}

type totpSetupPageData struct {
	PageData
	Secret string
	QRCode string // base64-encoded PNG
	Error  string
}

// pendingTOTP tracks users who passed password auth but still need TOTP verification.
var pendingTOTP = struct {
	sync.Mutex
	tokens map[string]pendingTOTPEntry
}{tokens: make(map[string]pendingTOTPEntry)}

type pendingTOTPEntry struct {
	UserID    uint64
	ExpiresAt time.Time
}

// HandleSetup shows and processes the first-run superadmin creation form.
func (s *Server) HandleSetup(w http.ResponseWriter, r *http.Request) {
	count, err := s.DB.CountUsers()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	if count > 0 {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodGet {
		s.renderStandalone(w, http.StatusOK, "setup.html", setupPageData{})
		return
	}

	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	username := r.FormValue("username")

	if username == "" {
		s.renderStandalone(w, http.StatusUnprocessableEntity, "setup.html",
			setupPageData{Error: "Username is required."})
		return
	}

	// Default password — user will be forced to change it on first login.
	hash, err := bcrypt.GenerateFromPassword([]byte("lssbackuppassword"), bcrypt.DefaultCost)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	uid, err := s.DB.CreateUser(username, string(hash), "superadmin")
	if err != nil {
		logx.FromContext(r.Context()).Error("setup create user failed", "err", err.Error())
		s.renderStandalone(w, http.StatusUnprocessableEntity, "setup.html",
			setupPageData{Error: "Could not create user: " + err.Error()})
		return
	}

	s.auditServerFor(r, nil, "user_created", "critical", "create", "user",
		strconv.FormatUint(uid, 10),
		"Initial superadmin created",
		map[string]string{"username": username, "role": "superadmin"})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HandleLogin shows and processes the login form.
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderStandalone(w, http.StatusOK, "login.html", loginPageData{})
		return
	}

	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	ip := r.RemoteAddr
	if !checkLoginAttempts(ip, username) {
		s.renderStandalone(w, http.StatusTooManyRequests, "login.html",
			loginPageData{Error: "Too many login attempts. Please try again later."})
		return
	}

	user, err := s.DB.GetUserByLogin(username)
	if err != nil {
		logx.FromContext(r.Context()).Error("get user failed", "err", err.Error())
		s.renderStandalone(w, http.StatusInternalServerError, "login.html",
			loginPageData{Error: "An error occurred. Please try again."})
		return
	}

	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		recordLoginFailure(r.RemoteAddr)
		logx.FromContext(r.Context()).Warn("login failed", "user", username, "ip", r.RemoteAddr)
		s.auditServerFor(r, nil, "auth_login_failed", "warn", "login_failed", "user", "",
			"Failed login attempt for "+username,
			map[string]string{"username": username})
		s.renderStandalone(w, http.StatusUnauthorized, "login.html",
			loginPageData{Error: "Invalid username or password."})
		return
	}

	// If 2FA is enabled, redirect to TOTP verification.
	if user.TOTPEnabled {
		token, err := generateSessionToken()
		if err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}

		pendingTOTP.Lock()
		pendingTOTP.tokens[token] = pendingTOTPEntry{
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		pendingTOTP.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "totp_pending",
			Value:    token,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		return
	}

	s.completeLogin(w, r, user)
}

// HandleTOTPVerify shows and processes the 2FA verification page.
func (s *Server) HandleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderStandalone(w, http.StatusOK, "totp_verify.html", totpVerifyPageData{})
		return
	}

	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	cookie, err := r.Cookie("totp_pending")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	pendingTOTP.Lock()
	entry, ok := pendingTOTP.tokens[cookie.Value]
	if ok && time.Now().After(entry.ExpiresAt) {
		delete(pendingTOTP.tokens, cookie.Value)
		ok = false
	}
	pendingTOTP.Unlock()

	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, err := s.DB.GetUserByID(entry.UserID)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	code := r.FormValue("code")
	if !totp.Validate(code, user.TOTPSecret) {
		recordLoginFailure(r.RemoteAddr)
		logx.FromContext(r.Context()).Warn("2fa failed", "user", user.Username, "ip", r.RemoteAddr)
		s.auditServerFor(r, user, "auth_2fa_failed", "warn", "2fa_failed", "user",
			strconv.FormatUint(user.ID, 10),
			"Failed 2FA verification for "+user.Username, nil)
		s.renderStandalone(w, http.StatusUnauthorized, "totp_verify.html",
			totpVerifyPageData{Error: "Invalid code. Please try again."})
		return
	}

	// Clean up pending token.
	pendingTOTP.Lock()
	delete(pendingTOTP.tokens, cookie.Value)
	pendingTOTP.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "totp_pending", MaxAge: -1, Path: "/"})

	s.completeLogin(w, r, user)
}

// completeLogin creates a session and redirects to the dashboard.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, user *models.User) {
	token, err := generateSessionToken()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	expiresAt := time.Now().Add(time.Duration(s.Config.Session.MaxAgeHours) * time.Hour)
	if err := s.DB.CreateSession(token, user.ID, expiresAt); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	logx.FromContext(r.Context()).Info("login ok", "user", user.Username, "role", user.Role, "ip", r.RemoteAddr, "twofa", user.TOTPEnabled)
	s.auditServerFor(r, user, "auth_login", "info", "login", "user",
		strconv.FormatUint(user.ID, 10),
		"Logged in as "+user.Username,
		map[string]string{"role": string(user.Role), "2fa": fmt.Sprintf("%t", user.TOTPEnabled)})
	s.setSessionCookie(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleTOTPSetup shows the QR code and processes TOTP enrollment.
func (s *Server) HandleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		// Generate a new TOTP key.
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "LSS Backup",
			AccountName: user.Username,
		})
		if err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}

		// Store the secret (not yet enabled).
		if err := s.DB.SetTOTPSecret(user.ID, key.Secret()); err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}

		// Generate QR code as base64 PNG.
		img, err := key.Image(200, 200)
		if err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}
		qrB64 := base64.StdEncoding.EncodeToString(buf.Bytes())

		s.render(w, r, http.StatusOK, "totp_setup.html", totpSetupPageData{
			PageData: s.newPageData(r),
			Secret:   key.Secret(),
			QRCode:   qrB64,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	// Verify the code to confirm setup.
	code := r.FormValue("code")

	// Re-read user to get the secret we just saved.
	user, err := s.DB.GetUserByID(user.ID)
	if err != nil || user == nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	if !totp.Validate(code, user.TOTPSecret) {
		// Regenerate QR for retry.
		key, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "LSS Backup",
			AccountName: user.Username,
		})
		_ = s.DB.SetTOTPSecret(user.ID, key.Secret())
		img, _ := key.Image(200, 200)
		var buf bytes.Buffer
		_ = png.Encode(&buf, img)

		s.render(w, r, http.StatusOK, "totp_setup.html", totpSetupPageData{
			PageData: s.newPageData(r),
			Secret:   key.Secret(),
			QRCode:   base64.StdEncoding.EncodeToString(buf.Bytes()),
			Error:    "Invalid code. A new QR code has been generated — please scan again.",
		})
		return
	}

	if err := s.DB.EnableTOTP(user.ID); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	logx.FromContext(r.Context()).Info("2fa enabled", "user", user.Username)
	s.auditServerFor(r, user, "auth_2fa_enabled", "info", "2fa_enable", "user",
		strconv.FormatUint(user.ID, 10), "2FA enabled for "+user.Username, nil)
	setFlash(w, "Two-factor authentication has been enabled.")
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// HandleTOTPDisable turns off 2FA for the current user.
func (s *Server) HandleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := s.DB.DisableTOTP(user.ID); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	logx.FromContext(r.Context()).Info("2fa disabled", "user", user.Username)
	s.auditServerFor(r, user, "auth_2fa_disabled", "warn", "2fa_disable", "user",
		strconv.FormatUint(user.ID, 10), "2FA disabled for "+user.Username, nil)
	setFlash(w, "Two-factor authentication has been disabled.")
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// HandleLogout deletes the session and clears the cookie.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	u, _ := r.Context().Value(ctxUser).(*models.User)
	if cookie, err := r.Cookie(s.Config.Session.CookieName); err == nil {
		ClearSessionSSHCreds(cookie.Value)
		if err := s.DB.DeleteSession(cookie.Value); err != nil {
			logx.FromContext(r.Context()).Warn("logout delete session failed", "err", err.Error())
		}
	}
	if u != nil {
		s.auditServerFor(r, u, "auth_logout", "info", "logout", "user",
			strconv.FormatUint(u.ID, 10), "Logged out "+u.Username, nil)
	}

	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
