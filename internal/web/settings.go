package web

import (
	"log"
	"net/http"

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
		log.Printf("settings: bcrypt: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := s.DB.UpdateUserPassword(user.ID, string(hash)); err != nil {
		log.Printf("settings: update password: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

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
		log.Printf("force-password: bcrypt: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := s.DB.UpdateUserPassword(user.ID, string(hash)); err != nil {
		log.Printf("force-password: update: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("auth: forced password change user=%q", user.Username)
	// Next request will hit RequireAuth which will redirect to 2FA setup.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
