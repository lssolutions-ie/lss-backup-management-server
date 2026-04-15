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
	Users        []*models.User
	GroupsByUser map[uint64][]*models.ClientGroup
	TagsByUser   map[uint64][]models.UserTag
}

type userFormPageData struct {
	PageData
	TargetUser  *models.User
	Groups      []*models.ClientGroup
	Assigned    map[uint64]bool
	AllUserTags []*models.UserTag
	UserTagIDs  map[uint64]bool
	Error       string
}

func (s *Server) HandleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.DB.ListUsers()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	allGroups, err := s.DB.ListClientGroups()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	groupByID := make(map[uint64]*models.ClientGroup, len(allGroups))
	for _, g := range allGroups {
		groupByID[g.ID] = g
	}

	groupsByUser := make(map[uint64][]*models.ClientGroup, len(users))
	for _, u := range users {
		if u.IsSuperAdmin() || u.IsManager() {
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

	tagsByUser, _ := s.DB.GetAllUserTagsByUser()

	s.render(w, r, http.StatusOK, "users.html", usersPageData{
		PageData:     s.newPageData(r),
		Users:        users,
		GroupsByUser: groupsByUser,
		TagsByUser:  tagsByUser,
	})
}

func (s *Server) HandleUserNew(w http.ResponseWriter, r *http.Request) {
	groups, err := s.DB.ListClientGroups()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	allUserTags, _ := s.DB.ListUserTags()

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "user_form.html", userFormPageData{
			PageData:    s.newPageData(r),
			Groups:      groups,
			Assigned:    map[uint64]bool{},
			AllUserTags: allUserTags,
			UserTagIDs:  map[uint64]bool{},
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	role := r.FormValue("role")
	if role != "superadmin" && role != "manager" && role != "user" && role != "guest" {
		role = "user"
	}

	if username == "" || email == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "user_form.html", userFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Assigned: formGroupSet(r),
			Error:    "Username and email are required.",
		})
		return
	}

	// All new users get the default password and are forced to change it on first login.
	hash, err := bcrypt.GenerateFromPassword([]byte("lssbackuppassword"), bcrypt.DefaultCost)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	userID, err := s.DB.CreateUserWithEmail(username, email, string(hash), role)
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

	if role == "user" || role == "guest" {
		groupIDs := parseGroupIDs(r)
		if err := s.DB.SetUserClientGroupAccess(userID, groupIDs); err != nil {
			log.Printf("user new: set access: %v", err)
		}
	}

	// Save user tags.
	tagIDs := parseTagIDs(r)
	if len(tagIDs) > 0 {
		if err := s.DB.SetUserTagsForUser(userID, tagIDs); err != nil {
			log.Printf("user new: set tags: %v", err)
		}
	}

	s.auditServer(r, "user_created", "info", "create", "user",
		strconv.FormatUint(userID, 10),
		"Created user "+username,
		map[string]string{"username": username, "email": email, "role": role})

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
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	assignedIDs, err := s.DB.GetUserClientGroupIDs(target.ID)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	assigned := make(map[uint64]bool, len(assignedIDs))
	for _, id := range assignedIDs {
		assigned[id] = true
	}

	allUserTags, _ := s.DB.ListUserTags()
	userTags, _ := s.DB.GetUserTagsForUser(target.ID)
	userTagIDs := make(map[uint64]bool, len(userTags))
	for _, t := range userTags {
		userTagIDs[t.ID] = true
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "user_form.html", userFormPageData{
			PageData:    s.newPageData(r),
			TargetUser:  target,
			Groups:      groups,
			Assigned:    assigned,
			AllUserTags: allUserTags,
			UserTagIDs:  userTagIDs,
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	role := r.FormValue("role")
	if role != "superadmin" && role != "manager" && role != "user" && role != "guest" {
		role = "user"
	}

	if err := s.DB.UpdateUserEmail(target.ID, email); err != nil {
		log.Printf("user edit: update email: %v", err)
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
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}
		if err := s.DB.UpdateUserPassword(target.ID, string(hash)); err != nil {
			s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
			return
		}
	}

	if err := s.DB.UpdateUser(target.ID, role); err != nil {
		log.Printf("user edit: update role: %v", err)
	}

	groupIDs := parseGroupIDs(r)
	if role == "user" || role == "guest" {
		if err := s.DB.SetUserClientGroupAccess(target.ID, groupIDs); err != nil {
			log.Printf("user edit: set access: %v", err)
		}
	} else {
		// superadmin/manager: clear explicit access (they see everything)
		_ = s.DB.SetUserClientGroupAccess(target.ID, nil)
	}

	// Save user tags.
	tagIDs := parseTagIDs(r)
	if err := s.DB.SetUserTagsForUser(target.ID, tagIDs); err != nil {
		log.Printf("user edit: set tags: %v", err)
	}

	details := map[string]string{"username": target.Username, "email": email, "role": role}
	if password != "" {
		details["password_changed"] = "true"
	}
	s.auditServer(r, "user_updated", "info", "update", "user",
		strconv.FormatUint(target.ID, 10),
		"Updated user "+target.Username, details)

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

	s.auditServer(r, "user_deleted", "critical", "delete", "user",
		strconv.FormatUint(target.ID, 10),
		"Deleted user "+target.Username,
		map[string]string{"username": target.Username, "role": string(target.Role)})

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
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
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

func parseTagIDs(r *http.Request) []uint64 {
	if err := r.ParseForm(); err != nil {
		return nil
	}
	values := r.Form["tag_ids"]
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
