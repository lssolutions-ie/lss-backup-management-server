package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type userTagUserInfo struct {
	ID   uint64
	Name string
}

type userTagsPageData struct {
	PageData
	UserTags    []*models.UserTag
	UsersByTag  map[uint64][]userTagUserInfo
}

type userTagEditPageData struct {
	PageData
	Tag   *models.UserTag
	Error string
}

// HandleUserTags lists all user tags (superadmin only).
func (s *Server) HandleUserTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.DB.ListUserTags()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	tagIDs := make([]uint64, len(tags))
	for i, t := range tags {
		tagIDs[i] = t.ID
	}
	usage, _ := s.DB.GetUsersUsingUserTags(tagIDs)
	usersByTag := make(map[uint64][]userTagUserInfo, len(usage))
	for tagID, entries := range usage {
		for _, e := range entries {
			usersByTag[tagID] = append(usersByTag[tagID], userTagUserInfo{ID: e.UserID, Name: e.Username})
		}
	}

	s.render(w, r, http.StatusOK, "user_tags.html", userTagsPageData{
		PageData:   s.newPageData(r),
		UserTags:   tags,
		UsersByTag: usersByTag,
	})
}

// HandleUserTagCreate POST /user-tags/new
func (s *Server) HandleUserTagCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}
	color := r.FormValue("color")
	textColor := r.FormValue("text_color")
	id, err := s.DB.CreateUserTag(name, color, textColor)
	if err != nil {
		log.Printf("user tag create: %v", err)
		setFlash(w, "Could not create user tag (name may already exist).")
	} else {
		s.auditServer(r, "user_tag_created", "info", "create", "user_tag",
			strconv.FormatUint(id, 10),
			"Created user tag "+name,
			map[string]string{"name": name, "color": color})
		setFlash(w, "User tag created.")
	}
	http.Redirect(w, r, "/user-tags", http.StatusSeeOther)
}

// HandleUserTagEdit GET/POST /user-tags/{id}/edit
func (s *Server) HandleUserTagEdit(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/user-tags/")
	idStr = strings.TrimSuffix(idStr, "/edit")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tag, err := s.DB.GetUserTagByID(id)
	if err != nil || tag == nil {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "user_tag_edit.html", userTagEditPageData{
			PageData: s.newPageData(r),
			Tag:      tag,
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "user_tag_edit.html", userTagEditPageData{
			PageData: s.newPageData(r),
			Tag:      tag,
			Error:    "Name is required.",
		})
		return
	}
	color := r.FormValue("color")
	textColor := r.FormValue("text_color")
	if err := s.DB.UpdateUserTag(id, name, color, textColor); err != nil {
		log.Printf("user tag edit: %v", err)
	}
	s.auditServer(r, "user_tag_updated", "info", "update", "user_tag",
		strconv.FormatUint(id, 10),
		"Updated user tag "+name,
		map[string]string{"name": name, "color": color})
	setFlash(w, "User tag updated.")
	http.Redirect(w, r, "/user-tags", http.StatusSeeOther)
}

// HandleUserTagCheckUsage returns, for each user_tag_id in the form, which users have it.
func (s *Server) HandleUserTagCheckUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var ids []uint64
	for _, v := range r.Form["tag_ids"] {
		if id, err := strconv.ParseUint(v, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	usage, err := s.DB.GetUsersUsingUserTags(ids)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var parts []string
	for _, entries := range usage {
		for _, e := range entries {
			parts = append(parts, `{"tag_name":"`+jsonEscape(e.TagName)+`","user_name":"`+jsonEscape(e.Username)+`"}`)
		}
	}
	w.Write([]byte(`{"assignments":[` + strings.Join(parts, ",") + `]}`))
}

func jsonEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// HandleUserTagBulkDelete deletes multiple user tags (POST /user-tags/bulk-delete).
func (s *Server) HandleUserTagBulkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var count int
	for _, v := range r.Form["tag_ids"] {
		id, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			continue
		}
		if err := s.DB.DeleteUserTag(id); err != nil {
			log.Printf("user tag bulk delete: %v", err)
			continue
		}
		count++
	}
	s.auditServer(r, "user_tag_bulk_deleted", "warn", "delete", "user_tag", "",
		fmt.Sprintf("Bulk deleted %d user tag(s)", count),
		map[string]string{"count": strconv.Itoa(count)})
	setFlash(w, strconv.Itoa(count)+" user tag(s) deleted.")
	http.Redirect(w, r, "/user-tags", http.StatusSeeOther)
}

// HandleUserTagDelete POST /user-tags/{id}/delete
func (s *Server) HandleUserTagDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/user-tags/")
	idStr = strings.TrimSuffix(idStr, "/delete")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.DeleteUserTag(id); err != nil {
		log.Printf("user tag delete: %v", err)
	}
	s.auditServer(r, "user_tag_deleted", "warn", "delete", "user_tag",
		strconv.FormatUint(id, 10), "Deleted user tag", nil)
	setFlash(w, "User tag deleted.")
	http.Redirect(w, r, "/user-tags", http.StatusSeeOther)
}
