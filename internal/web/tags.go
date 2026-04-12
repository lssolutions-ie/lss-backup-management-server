package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type tagsPageData struct {
	PageData
	Tags  []*models.Tag
}

type tagEditPageData struct {
	PageData
	Tag       *models.Tag
	Users     []*models.User
	Assigned  map[uint64]bool
	Error     string
}

// HandleTags lists all tags.
func (s *Server) HandleTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.DB.ListTags()
	if err != nil {
		log.Printf("tags: list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	s.render(w, r, http.StatusOK, "tags.html", tagsPageData{
		PageData: s.newPageData(r),
		Tags:     tags,
	})
}

// HandleTagEdit shows and processes the tag edit form.
func (s *Server) HandleTagEdit(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/tags/")
	idStr = strings.TrimSuffix(idStr, "/edit")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	tag, err := s.DB.GetTagByID(id)
	if err != nil || tag == nil {
		http.NotFound(w, r)
		return
	}

	users, err := s.DB.ListUsers()
	if err != nil {
		log.Printf("tag edit: list users: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	assignedIDs, _ := s.DB.GetTagUserIDs(id)
	assigned := make(map[uint64]bool)
	for _, uid := range assignedIDs {
		assigned[uid] = true
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "tag_edit.html", tagEditPageData{
			PageData: s.newPageData(r),
			Tag:      tag,
			Users:    users,
			Assigned: assigned,
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	color := r.FormValue("color")
	if name == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "tag_edit.html", tagEditPageData{
			PageData: s.newPageData(r),
			Tag:      tag,
			Users:    users,
			Assigned: assigned,
			Error:    "Tag name is required.",
		})
		return
	}

	textColor := r.FormValue("text_color")
	if textColor == "" {
		textColor = "#ffffff"
	}

	if err := s.DB.UpdateTag(id, name, color, textColor); err != nil {
		log.Printf("tag edit: update: %v", err)
	}

	// Update user permissions.
	var userIDs []uint64
	for _, v := range r.Form["user_ids"] {
		if uid, err := strconv.ParseUint(v, 10, 64); err == nil {
			userIDs = append(userIDs, uid)
		}
	}
	if err := s.DB.SetTagUsers(id, userIDs); err != nil {
		log.Printf("tag edit: set users: %v", err)
	}

	setFlash(w, "Tag updated.")
	http.Redirect(w, r, "/tags", http.StatusSeeOther)
}

// HandleTagCreate creates a new tag.
func (s *Server) HandleTagCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	color := r.FormValue("color")
	if color == "" {
		color = "#206bc4"
	}
	if name == "" {
		http.Error(w, "Tag name is required", http.StatusBadRequest)
		return
	}

	textColor := r.FormValue("text_color")
	if textColor == "" {
		textColor = "#ffffff"
	}
	if _, err := s.DB.CreateTagWithTextColor(name, color, textColor); err != nil {
		log.Printf("tag create: %v", err)
		setFlash(w, "Could not create tag (name may already exist).")
	} else {
		setFlash(w, "Tag created.")
	}

	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/tags"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// HandleTagDelete deletes a tag.
func (s *Server) HandleTagDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/tags/")
	idStr = strings.TrimSuffix(idStr, "/delete")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := s.DB.DeleteTag(id); err != nil {
		log.Printf("tag delete: %v", err)
	}
	setFlash(w, "Tag deleted.")

	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/tags"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
