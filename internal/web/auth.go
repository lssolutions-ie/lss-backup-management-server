package web

import (
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type loginPageData struct {
	PageData
	Error string
}

type setupPageData struct {
	Error string
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
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	if username == "" || password == "" {
		s.renderStandalone(w, http.StatusUnprocessableEntity, "setup.html",
			setupPageData{Error: "Username and password are required."})
		return
	}
	if password != confirm {
		s.renderStandalone(w, http.StatusUnprocessableEntity, "setup.html",
			setupPageData{Error: "Passwords do not match."})
		return
	}
	if len(password) < 8 {
		s.renderStandalone(w, http.StatusUnprocessableEntity, "setup.html",
			setupPageData{Error: "Password must be at least 8 characters."})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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
		log.Printf("auth: login failed user=%q ip=%s", username, r.RemoteAddr)
		s.renderStandalone(w, http.StatusUnauthorized, "login.html",
			loginPageData{Error: "Invalid username or password."})
		return
	}

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

	log.Printf("auth: login ok user=%q role=%s ip=%s", user.Username, user.Role, r.RemoteAddr)
	s.setSessionCookie(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
