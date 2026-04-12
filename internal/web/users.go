package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type usersPageData struct {
	PageData
	Users       []*models.User
	GroupsByUser map[uint64][]*models.ClientGroup
}

type userFormPageData struct {
	PageData
	TargetUser *models.User
	Groups     []*models.ClientGroup
	Assigned   map[uint64]bool
	Error      string
}

func (s *Server) HandleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.DB.ListUsers()
	if err != nil {
		log.Printf("users: list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	allGroups, err := s.DB.ListClientGroups()
	if err != nil {
		log.Printf("users: list groups: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	groupByID := make(map[uint64]*models.ClientGroup, len(allGroups))
	for _, g := range allGroups {
		groupByID[g.ID] = g
	}

	groupsByUser := make(map[uint64][]*models.ClientGroup, len(users))
	for _, u := range users {
		if u.IsSuperAdmin() {
			continue
		}
		ids, err := s.DB.GetUserClientGroupIDs(u.ID)
		if err != nil {
			log.Printf("users: get group ids: %v", err)
			continue
		}
		for _, id := range ids {
			if g, ok := groupByID[id]; ok {
				groupsByUser[u.ID] = append(groupsByUser[u.ID], g)
			}
		}
	}

	s.render(w, r, http.StatusOK, "users.html", usersPageData{
		PageData:     s.newPageData(r),
		Users:        users,
		GroupsByUser: groupsByUser,
	})
}

func (s *Server) HandleUserNew(w http.ResponseWriter, r *http.Request) {
	groups, err := s.DB.ListClientGroups()
	if err != nil {
		log.Printf("user new: list groups: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "user_form.html", userFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Assigned: map[uint64]bool{},
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	role := r.FormValue("role")
	if role != "superadmin" && role != "user" && role != "viewer" {
		role = "user"
	}

	if username == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "user_form.html", userFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Assigned: formGroupSet(r),
			Error:    "Username is required.",
		})
		return
	}

	// All new users get the default password and are forced to change it on first login.
	hash, err := bcrypt.GenerateFromPassword([]byte("lssbackuppassword"), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("user new: bcrypt: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	userID, err := s.DB.CreateUser(username, string(hash), role)
	if err != nil {
		log.Printf("user new: create: %v", err)
		s.render(w, r, http.StatusUnprocessableEntity, "user_form.html", userFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Assigned: formGroupSet(r),
			Error:    "Could not create user (username may already be taken).",
		})
		return
	}

	if role != "superadmin" {
		groupIDs := parseGroupIDs(r)
		if err := s.DB.SetUserClientGroupAccess(userID, groupIDs); err != nil {
			log.Printf("user new: set access: %v", err)
		}
	}

	setFlash(w, "User created.")
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) HandleUserEdit(w http.ResponseWriter, r *http.Request) {
	target, ok := s.userFromPath(w, r)
	if !ok {
		return
	}

	groups, err := s.DB.ListClientGroups()
	if err != nil {
		log.Printf("user edit: list groups: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	assignedIDs, err := s.DB.GetUserClientGroupIDs(target.ID)
	if err != nil {
		log.Printf("user edit: get access: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	assigned := make(map[uint64]bool, len(assignedIDs))
	for _, id := range assignedIDs {
		assigned[id] = true
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "user_form.html", userFormPageData{
			PageData:   s.newPageData(r),
			TargetUser: target,
			Groups:     groups,
			Assigned:   assigned,
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	password := r.FormValue("password")
	role := r.FormValue("role")
	if role != "superadmin" && role != "user" && role != "viewer" {
		role = "user"
	}

	if password != "" {
		if len(password) < 8 {
			s.render(w, r, http.StatusUnprocessableEntity, "user_form.html", userFormPageData{
				PageData:   s.newPageData(r),
				TargetUser: target,
				Groups:     groups,
				Assigned:   formGroupSet(r),
				Error:      "Password must be at least 8 characters.",
			})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("user edit: bcrypt: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if err := s.DB.UpdateUserPassword(target.ID, string(hash)); err != nil {
			log.Printf("user edit: update password: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	if err := s.DB.UpdateUser(target.ID, role); err != nil {
		log.Printf("user edit: update role: %v", err)
	}

	groupIDs := parseGroupIDs(r)
	if role != "superadmin" {
		if err := s.DB.SetUserClientGroupAccess(target.ID, groupIDs); err != nil {
			log.Printf("user edit: set access: %v", err)
		}
	} else {
		// superadmin: clear explicit access (they see everything)
		_ = s.DB.SetUserClientGroupAccess(target.ID, nil)
	}

	setFlash(w, "User updated.")
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) HandleUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	target, ok := s.userFromPath(w, r)
	if !ok {
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	currentUser := r.Context().Value(ctxUser).(*models.User)
	if currentUser.ID == target.ID {
		setFlash(w, "You cannot delete your own account.")
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	if err := s.DB.DeleteUser(target.ID); err != nil {
		log.Printf("user delete: %v", err)
		setFlash(w, "Could not delete user.")
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}

	setFlash(w, "User deleted.")
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) userFromPath(w http.ResponseWriter, r *http.Request) (*models.User, bool) {
	rest := strings.TrimPrefix(r.URL.Path, "/users/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	u, err := s.DB.GetUserByID(id)
	if err != nil {
		log.Printf("userFromPath: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}
	if u == nil {
		http.NotFound(w, r)
		return nil, false
	}
	return u, true
}

func parseGroupIDs(r *http.Request) []uint64 {
	if err := r.ParseForm(); err != nil {
		return nil
	}
	values := r.Form["client_group_ids"]
	ids := make([]uint64, 0, len(values))
	for _, v := range values {
		id, err := strconv.ParseUint(v, 10, 64)
		if err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func formGroupSet(r *http.Request) map[uint64]bool {
	set := make(map[uint64]bool)
	for _, id := range parseGroupIDs(r) {
		set[id] = true
	}
	return set
}
