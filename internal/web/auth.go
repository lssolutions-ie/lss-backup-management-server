package web

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"log"
	"net/http"
	"sync"
	"time"

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
		log.Printf("setup: count users: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		log.Printf("setup: bcrypt: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if _, err := s.DB.CreateUser(username, string(hash), "superadmin"); err != nil {
		log.Printf("setup: create user: %v", err)
		s.renderStandalone(w, http.StatusUnprocessableEntity, "setup.html",
			setupPageData{Error: "Could not create user: " + err.Error()})
		return
	}

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

	user, err := s.DB.GetUserByUsername(username)
	if err != nil {
		log.Printf("login: get user: %v", err)
		s.renderStandalone(w, http.StatusInternalServerError, "login.html",
			loginPageData{Error: "An error occurred. Please try again."})
		return
	}

	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		recordLoginFailure(r.RemoteAddr)
		log.Printf("auth: login failed user=%q ip=%s", username, r.RemoteAddr)
		s.renderStandalone(w, http.StatusUnauthorized, "login.html",
			loginPageData{Error: "Invalid username or password."})
		return
	}

	// If 2FA is enabled, redirect to TOTP verification.
	if user.TOTPEnabled {
		token, err := generateSessionToken()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		log.Printf("auth: 2fa failed user=%q ip=%s", user.Username, r.RemoteAddr)
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
		log.Printf("login: generate token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(time.Duration(s.Config.Session.MaxAgeHours) * time.Hour)
	if err := s.DB.CreateSession(token, user.ID, expiresAt); err != nil {
		log.Printf("login: create session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("auth: login ok user=%q role=%s ip=%s 2fa=%v", user.Username, user.Role, r.RemoteAddr, user.TOTPEnabled)
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
			log.Printf("totp setup: generate: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Store the secret (not yet enabled).
		if err := s.DB.SetTOTPSecret(user.ID, key.Secret()); err != nil {
			log.Printf("totp setup: save secret: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Generate QR code as base64 PNG.
		img, err := key.Image(200, 200)
		if err != nil {
			log.Printf("totp setup: qr image: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			log.Printf("totp setup: png encode: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		log.Printf("totp setup: enable: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("auth: 2fa enabled user=%q", user.Username)
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
		log.Printf("totp disable: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("auth: 2fa disabled user=%q", user.Username)
	setFlash(w, "Two-factor authentication has been disabled.")
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// HandleLogout deletes the session and clears the cookie.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if cookie, err := r.Cookie(s.Config.Session.CookieName); err == nil {
		if err := s.DB.DeleteSession(cookie.Value); err != nil {
			log.Printf("logout: delete session: %v", err)
		}
	}

	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
