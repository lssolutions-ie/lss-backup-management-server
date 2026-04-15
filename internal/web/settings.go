package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"time"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type settingsPageData struct {
	PageData
	Error   string
	Success string
}

func (s *Server) HandleSettings(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(ctxUser).(*models.User)

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "settings.html", settingsPageData{
			PageData: s.newPageData(r),
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	current := r.FormValue("current_password")
	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if current == "" || newPw == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "settings.html", settingsPageData{
			PageData: s.newPageData(r),
			Error:    "All fields are required.",
		})
		return
	}
	if newPw != confirm {
		s.render(w, r, http.StatusUnprocessableEntity, "settings.html", settingsPageData{
			PageData: s.newPageData(r),
			Error:    "New passwords do not match.",
		})
		return
	}
	if len(newPw) < 8 {
		s.render(w, r, http.StatusUnprocessableEntity, "settings.html", settingsPageData{
			PageData: s.newPageData(r),
			Error:    "New password must be at least 8 characters.",
		})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)) != nil {
		s.render(w, r, http.StatusUnauthorized, "settings.html", settingsPageData{
			PageData: s.newPageData(r),
			Error:    "Current password is incorrect.",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPw), bcrypt.DefaultCost)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	if err := s.DB.UpdateUserPassword(user.ID, string(hash)); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	s.auditServerFor(r, user, "user_password_changed", "warn", "update", "user",
		strconv.FormatUint(user.ID, 10),
		"Changed own password for "+user.Username,
		map[string]string{"username": user.Username})

	s.render(w, r, http.StatusOK, "settings.html", settingsPageData{
		PageData: s.newPageData(r),
		Success:  "Password updated successfully.",
	})
}

type forcePasswordPageData struct {
	PageData
	Error string
}

// HandleForcePassword handles the mandatory password change on first login.
func (s *Server) HandleForcePassword(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(ctxUser).(*models.User)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "force_password.html", forcePasswordPageData{
			PageData: s.newPageData(r),
		})
		return
	}

	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if newPw == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "force_password.html", forcePasswordPageData{
			PageData: s.newPageData(r),
			Error:    "Password is required.",
		})
		return
	}
	if newPw != confirm {
		s.render(w, r, http.StatusUnprocessableEntity, "force_password.html", forcePasswordPageData{
			PageData: s.newPageData(r),
			Error:    "Passwords do not match.",
		})
		return
	}
	if len(newPw) < 8 {
		s.render(w, r, http.StatusUnprocessableEntity, "force_password.html", forcePasswordPageData{
			PageData: s.newPageData(r),
			Error:    "Password must be at least 8 characters.",
		})
		return
	}
	if newPw == "lssbackuppassword" {
		s.render(w, r, http.StatusUnprocessableEntity, "force_password.html", forcePasswordPageData{
			PageData: s.newPageData(r),
			Error:    "You cannot reuse the default password.",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPw), bcrypt.DefaultCost)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	if err := s.DB.UpdateUserPassword(user.ID, string(hash)); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	s.auditServerFor(r, user, "user_password_changed", "warn", "update", "user",
		strconv.FormatUint(user.ID, 10),
		"Forced password change for "+user.Username,
		map[string]string{"username": user.Username, "forced": "true"})

	logx.FromContext(r.Context()).Info("forced password change", "user", user.Username)
	// Next request will hit RequireAuth which will redirect to 2FA setup.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type smtpPageData struct {
	PageData
	SMTP    *models.SMTPConfig
	Error   string
	Success string
}

// HandleSMTPSettings shows and processes the SMTP configuration form.
func (s *Server) HandleSMTPSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.DB.GetSMTPConfig()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	// Decrypt password for display (masked in template).
	if cfg.PasswordEnc != "" {
		if pw, err := decryptSMTPPassword(cfg.PasswordEnc, s.AppKey); err == nil {
			cfg.PasswordEnc = pw
		}
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "smtp_settings.html", smtpPageData{
			PageData: s.newPageData(r),
			SMTP:     cfg,
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	port, _ := strconv.Atoi(r.FormValue("port"))
	if port == 0 {
		port = 587
	}

	password := r.FormValue("password")
	passwordEnc := ""
	if password != "" {
		enc, err := encryptSMTPPassword(password, s.AppKey)
		if err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}
		passwordEnc = enc
	} else if cfg.PasswordEnc != "" {
		// Keep existing password if not changed. Re-encrypt from the decrypted value.
		enc, err := encryptSMTPPassword(cfg.PasswordEnc, s.AppKey)
		if err == nil {
			passwordEnc = enc
		}
	}

	cfg = &models.SMTPConfig{
		Host:        r.FormValue("host"),
		Port:        port,
		Username:    r.FormValue("username"),
		PasswordEnc: passwordEnc,
		FromAddress: r.FormValue("from_address"),
		FromName:    r.FormValue("from_name"),
		UseTLS:      r.FormValue("use_tls") == "on",
		Enabled:     r.FormValue("enabled") == "on",
	}

	if err := s.DB.SaveSMTPConfig(cfg); err != nil {
		logx.FromContext(r.Context()).Error("save smtp config failed", "err", err.Error())
		s.render(w, r, http.StatusInternalServerError, "smtp_settings.html", smtpPageData{
			PageData: s.newPageData(r),
			SMTP:     cfg,
			Error:    "Failed to save configuration.",
		})
		return
	}

	s.auditServer(r, "smtp_config_saved", "warn", "save", "smtp_config", "",
		"Saved SMTP configuration",
		map[string]string{
			"host":         cfg.Host,
			"port":         strconv.Itoa(cfg.Port),
			"username":     cfg.Username,
			"from_address": cfg.FromAddress,
			"use_tls":      fmt.Sprintf("%t", cfg.UseTLS),
			"enabled":      fmt.Sprintf("%t", cfg.Enabled),
		})

	logx.FromContext(r.Context()).Info("smtp config updated")
	s.render(w, r, http.StatusOK, "smtp_settings.html", smtpPageData{
		PageData: s.newPageData(r),
		SMTP:     cfg,
		Success:  "SMTP configuration saved.",
	})
}

// HandleSMTPTest sends a test email using the saved SMTP config.
func (s *Server) HandleSMTPTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	user, _ := r.Context().Value(ctxUser).(*models.User)

	cfg, err := s.DB.GetSMTPConfig()
	if err != nil || cfg.Host == "" {
		s.render(w, r, http.StatusOK, "smtp_settings.html", smtpPageData{
			PageData: s.newPageData(r),
			SMTP:     cfg,
			Error:    "SMTP is not configured. Save configuration first.",
		})
		return
	}

	password := ""
	if cfg.PasswordEnc != "" {
		if pw, err := decryptSMTPPassword(cfg.PasswordEnc, s.AppKey); err == nil {
			password = pw
		}
	}

	to := ""
	if user.Email != nil {
		to = *user.Email
	}
	if to == "" {
		to = cfg.FromAddress
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	auth := smtp.PlainAuth("", cfg.Username, password, cfg.Host)

	msg := fmt.Sprintf("From: %s <%s>\r\nTo: %s\r\nSubject: LSS Backup — Test Email\r\n\r\nThis is a test email from LSS Backup Management Server.\r\nSent at: %s\r\n",
		cfg.FromName, cfg.FromAddress, to, time.Now().Format(time.RFC3339))

	var sendErr error
	if cfg.UseTLS {
		sendErr = smtp.SendMail(addr, auth, cfg.FromAddress, []string{to}, []byte(msg))
	} else {
		// Plain SMTP without TLS.
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			sendErr = err
		} else {
			c, err := smtp.NewClient(conn, cfg.Host)
			if err != nil {
				sendErr = err
			} else {
				defer c.Close()
				if err := c.Auth(auth); err != nil {
					sendErr = err
				} else if err := c.Mail(cfg.FromAddress); err != nil {
					sendErr = err
				} else if err := c.Rcpt(to); err != nil {
					sendErr = err
				} else {
					wc, err := c.Data()
					if err != nil {
						sendErr = err
					} else {
						_, _ = wc.Write([]byte(msg))
						sendErr = wc.Close()
					}
				}
			}
		}
	}

	// Re-read config for display (password already decrypted above).
	cfg.PasswordEnc = password

	if sendErr != nil {
		logx.FromContext(r.Context()).Warn("smtp test failed", "err", sendErr.Error())
		s.auditServer(r, "smtp_test", "warn", "test", "smtp_config", "",
			"SMTP test email failed",
			map[string]string{"to": to, "error": sendErr.Error()})
		s.render(w, r, http.StatusOK, "smtp_settings.html", smtpPageData{
			PageData: s.newPageData(r),
			SMTP:     cfg,
			Error:    "Test email failed: " + sendErr.Error(),
		})
		return
	}

	s.auditServer(r, "smtp_test", "info", "test", "smtp_config", "",
		"SMTP test email sent to "+to,
		map[string]string{"to": to})

	logx.FromContext(r.Context()).Info("smtp test sent", "to", to)
	s.render(w, r, http.StatusOK, "smtp_settings.html", smtpPageData{
		PageData: s.newPageData(r),
		SMTP:     cfg,
		Success:  "Test email sent to " + to,
	})
}

// encryptSMTPPassword encrypts a password using AES-GCM with the app key.
func encryptSMTPPassword(password string, key []byte) (string, error) {
	block, err := aes.NewCipher(key[:32])
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
	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptSMTPPassword decrypts a password using AES-GCM with the app key.
func decryptSMTPPassword(encoded string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
