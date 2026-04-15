package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type userGroupsPageData struct {
	PageData
	Groups           []*models.UserGroup
	ClientNames      map[uint64]string
	MemberCountByID  map[uint64]int
	TagCountByID     map[uint64]int
}

type userGroupFormPageData struct {
	PageData
	Group           *models.UserGroup // nil = create
	Clients         []*models.ClientGroup
	AllUsers        []*models.User
	AllUserTags     []*models.UserTag
	MemberIDs       map[uint64]bool
	LeadIDs         map[uint64]bool
	TagIDs          map[uint64]bool
	Error           string
}

// HandleUserGroups lists all user groups (superadmin only).
func (s *Server) HandleUserGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.DB.ListUserGroups()
	if err != nil {
		log.Printf("user-groups list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	clients, _ := s.DB.ListClientGroups()
	clientNames := make(map[uint64]string, len(clients))
	for _, c := range clients {
		clientNames[c.ID] = c.Name
	}
	memberCount := make(map[uint64]int, len(groups))
	tagCount := make(map[uint64]int, len(groups))
	for _, g := range groups {
		members, _ := s.DB.GetUserGroupMembers(g.ID)
		memberCount[g.ID] = len(members)
		tags, _ := s.DB.GetUserGroupTagIDs(g.ID)
		tagCount[g.ID] = len(tags)
	}
	s.render(w, r, http.StatusOK, "user_groups.html", userGroupsPageData{
		PageData:         s.newPageData(r),
		Groups:           groups,
		ClientNames:      clientNames,
		MemberCountByID:  memberCount,
		TagCountByID:     tagCount,
	})
}

// HandleUserGroupNew GET+POST /user-groups/new
func (s *Server) HandleUserGroupNew(w http.ResponseWriter, r *http.Request) {
	clients, err := s.DB.ListClientGroups()
	if err != nil {
		log.Printf("user-group new: clients: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	users, _ := s.DB.ListUsers()
	userTags, _ := s.DB.ListUserTags()

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "user_group_form.html", userGroupFormPageData{
			PageData:    s.newPageData(r),
			Clients:     clients,
			AllUsers:    users,
			AllUserTags: userTags,
			MemberIDs:   map[uint64]bool{},
			LeadIDs:     map[uint64]bool{},
			TagIDs:      map[uint64]bool{},
		})
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	clientIDStr := r.FormValue("client_group_id")
	if name == "" || clientIDStr == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "user_group_form.html", userGroupFormPageData{
			PageData:    s.newPageData(r),
			Clients:     clients,
			AllUsers:    users,
			AllUserTags: userTags,
			MemberIDs:   formUint64Set(r, "member_ids"),
			LeadIDs:     formUint64Set(r, "lead_ids"),
			TagIDs:      formUint64Set(r, "tag_ids"),
			Error:       "Name and client are required.",
		})
		return
	}
	clientID, err := strconv.ParseUint(clientIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Bad client id", http.StatusBadRequest)
		return
	}
	gid, err := s.DB.CreateUserGroup(name, clientID)
	if err != nil {
		log.Printf("user-group new: %v", err)
		s.render(w, r, http.StatusUnprocessableEntity, "user_group_form.html", userGroupFormPageData{
			PageData:    s.newPageData(r),
			Clients:     clients,
			AllUsers:    users,
			AllUserTags: userTags,
			MemberIDs:   formUint64Set(r, "member_ids"),
			LeadIDs:     formUint64Set(r, "lead_ids"),
			TagIDs:      formUint64Set(r, "tag_ids"),
			Error:       "Could not create group (name may be taken within this client).",
		})
		return
	}
	applyMembersAndTags(s, r, gid)
	s.auditServer(r, "user_group_created", "info", "create", "user_group",
		strconv.FormatUint(gid, 10),
		"Created user group "+name,
		map[string]string{"name": name, "client_group_id": strconv.FormatUint(clientID, 10)})
	setFlash(w, "User group created.")
	http.Redirect(w, r, "/user-groups", http.StatusSeeOther)
}

// HandleUserGroupEdit GET+POST /user-groups/{id}/edit
func (s *Server) HandleUserGroupEdit(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/user-groups/")
	idStr = strings.TrimSuffix(idStr, "/edit")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	group, err := s.DB.GetUserGroupByID(id)
	if err != nil || group == nil {
		http.NotFound(w, r)
		return
	}
	clients, _ := s.DB.ListClientGroups()
	users, _ := s.DB.ListUsers()
	userTags, _ := s.DB.ListUserTags()
	members, _ := s.DB.GetUserGroupMembers(id)
	memberIDs := make(map[uint64]bool, len(members))
	leadIDs := make(map[uint64]bool)
	for _, m := range members {
		memberIDs[m.UserID] = true
		if m.IsLead {
			leadIDs[m.UserID] = true
		}
	}
	tagIDsList, _ := s.DB.GetUserGroupTagIDs(id)
	tagIDs := make(map[uint64]bool, len(tagIDsList))
	for _, tid := range tagIDsList {
		tagIDs[tid] = true
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "user_group_form.html", userGroupFormPageData{
			PageData:    s.newPageData(r),
			Group:       group,
			Clients:     clients,
			AllUsers:    users,
			AllUserTags: userTags,
			MemberIDs:   memberIDs,
			LeadIDs:     leadIDs,
			TagIDs:      tagIDs,
		})
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	clientIDStr := r.FormValue("client_group_id")
	if name == "" || clientIDStr == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "user_group_form.html", userGroupFormPageData{
			PageData:    s.newPageData(r),
			Group:       group,
			Clients:     clients,
			AllUsers:    users,
			AllUserTags: userTags,
			MemberIDs:   formUint64Set(r, "member_ids"),
			LeadIDs:     formUint64Set(r, "lead_ids"),
			TagIDs:      formUint64Set(r, "tag_ids"),
			Error:       "Name and client are required.",
		})
		return
	}
	clientID, _ := strconv.ParseUint(clientIDStr, 10, 64)
	if err := s.DB.UpdateUserGroup(id, name, clientID); err != nil {
		log.Printf("user-group edit: %v", err)
	}
	applyMembersAndTags(s, r, id)
	s.auditServer(r, "user_group_updated", "info", "update", "user_group",
		strconv.FormatUint(id, 10),
		"Updated user group "+name,
		map[string]string{"name": name, "client_group_id": strconv.FormatUint(clientID, 10)})
	setFlash(w, "User group updated.")
	http.Redirect(w, r, "/user-groups", http.StatusSeeOther)
}

// HandleUserGroupDelete POST /user-groups/{id}/delete
func (s *Server) HandleUserGroupDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/user-groups/")
	idStr = strings.TrimSuffix(idStr, "/delete")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.DeleteUserGroup(id); err != nil {
		log.Printf("user-group delete: %v", err)
	}
	s.auditServer(r, "user_group_deleted", "warn", "delete", "user_group",
		strconv.FormatUint(id, 10), "Deleted user group", nil)
	setFlash(w, "User group deleted.")
	http.Redirect(w, r, "/user-groups", http.StatusSeeOther)
}

func applyMembersAndTags(s *Server, r *http.Request, groupID uint64) {
	_ = r.ParseForm()
	leadSet := formUint64Set(r, "lead_ids")
	var members []models.UserGroupMember
	for _, v := range r.Form["member_ids"] {
		uid, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			continue
		}
		members = append(members, models.UserGroupMember{
			UserGroupID: groupID,
			UserID:      uid,
			IsLead:      leadSet[uid],
		})
	}
	_ = s.DB.SetUserGroupMembers(groupID, members)
	var tagIDs []uint64
	for _, v := range r.Form["tag_ids"] {
		tid, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			continue
		}
		tagIDs = append(tagIDs, tid)
	}
	_ = s.DB.SetUserGroupTags(groupID, tagIDs)
}

func formUint64Set(r *http.Request, field string) map[uint64]bool {
	_ = r.ParseForm()
	out := make(map[uint64]bool)
	for _, v := range r.Form[field] {
		if id, err := strconv.ParseUint(v, 10, 64); err == nil {
			out[id] = true
		}
	}
	return out
}
